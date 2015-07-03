{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module Snap.Snaplet.Auth.Backends.Neo4j.Internal where

import Control.Applicative ( (<$>) )
import Control.Monad ( forM, forM_ )
import Control.Monad.IO.Class ( MonadIO, liftIO )
import Data.Maybe ( catMaybes )
import Data.String ( fromString )

import Data.Int ( Int64 )
import Data.List ( foldl' )
import Data.Time.Format ( formatTime, parseTime )
import Data.Word ( Word8 )
import Database.Neo4j ( (|:), Neo4j, Hostname, Port )
import Snap.Snaplet ( SnapletInit, SnapletLens, makeSnaplet )
import Snap.Snaplet.Auth
    ( AuthManager(..), AuthSettings(..), AuthUser(..), IAuthBackend(..))
import Snap.Snaplet.Session ( SessionManager )
import Snap.Snaplet.Session.Common ( mkRNG )
import System.Locale ( defaultTimeLocale, iso8601DateFormat )
import Web.ClientSession ( getKey )

import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BS (toChunks)
import qualified Data.HashMap.Strict as HM
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Encoding as T ( decodeUtf8, encodeUtf8 )
import qualified Database.Neo4j as Neo4j
import qualified Snap.Snaplet.Auth as Auth

import Snap.Snaplet.Neo4j.Internal ( Neo4jSnaplet(..) )
import Snap.Snaplet.Auth.Backends.Neo4j.Types ( PropertyNames(..) )

data Neo4jAuthManager = Neo4jAuthManager
  { neo4jSnaplet :: Neo4jSnaplet
  , propertyNames :: PropertyNames
  }

mkNeo4jAuthManager :: Hostname -> Port -> PropertyNames -> Neo4jAuthManager
mkNeo4jAuthManager hostname port =
    Neo4jAuthManager $ Neo4jSnaplet hostname port

initNeo4jAuthManager ::
  AuthSettings ->
  SnapletLens b SessionManager ->
  Neo4jSnaplet ->
  PropertyNames ->
  SnapletInit b (AuthManager b)
initNeo4jAuthManager (AuthSettings{..}) sessionManager neo4j
                     propertyNames@PropertyNames
                     { labelUser, labelRole, propLogin, propRememberToken
                     , propRole} =
    makeSnaplet "neo4j-auth" "Provides authentification via Neo4j" Nothing $
        liftIO $ do
          key  <- getKey asSiteKey
          rng  <- mkRNG
          withNeo4jSnaplet neo4j $ do
              createIndexIfNeeded labelUser propLogin
              createIndexIfNeeded labelUser propRememberToken
              createIndexIfNeeded labelRole propRole
          return $! AuthManager
            { backend = Neo4jAuthManager neo4j propertyNames
            , session = sessionManager
            , activeUser = Nothing
            , minPasswdLen = asMinPasswdLen
            , rememberCookieName = asRememberCookieName
            , rememberPeriod = asRememberPeriod
            , siteKey = key
            , lockout = asLockout
            , randomNumberGenerator = rng
            }

instance IAuthBackend Neo4jAuthManager where
  save (Neo4jAuthManager neo4j (propertyNames@PropertyNames
                                {labelUser, propLogin}))
       (authUser@AuthUser{userId, userLogin, userRoles}) = do
      withNeo4jSnaplet neo4j $ do
        properties <- liftIO $ authUserToProps propertyNames authUser
        case userId of
          -- Create case
          Nothing -> do
            nodes <- Neo4j.getNodesByLabelAndProperty labelUser $
                Just $ propLogin |: userLogin
                [ "Nodes with login \"", userLogin, "\": "
                , T.pack $ show $ length nodes
                ]
            case nodes of
              _:_ -> return $ Left Auth.DuplicateLogin
              [] -> do
                  node <- Neo4j.createNode properties
                  Neo4j.addLabels [labelUser] node
                  forM_ userRoles $ connectNodeToRole propertyNames node
                  let au = authUser
                          { userId = Just $ nodeToUserId node
                          }
                  return $ Right au

          -- Modify case
          Just userId' -> do
            mbNode <- Neo4j.getNode $ T.encodeUtf8 $ Auth.unUid userId'
            case mbNode of
              Just node -> do
                _ <- Neo4j.setProperties node properties
                syncRoles propertyNames node userRoles
                return $ Right $ authUser
              Nothing -> return $ Left $ Auth.UserNotFound

  lookupByUserId (Neo4jAuthManager neo4j propertyNames) userId =
      withNeo4jSnaplet neo4j $ do
        mbNode <- Neo4j.getNode $ T.encodeUtf8 $ Auth.unUid userId
        case mbNode of
          Just node -> do
            roles <- getRolesForNode propertyNames node
            return $ nodeToAuthUser propertyNames node roles
          Nothing -> return Nothing -- This is still less code than using MaybeT
  
  lookupByLogin = lookupByProperty propLogin

  lookupByRememberToken = lookupByProperty propRememberToken

  destroy (Neo4jAuthManager neo4j _) (AuthUser{userId}) = do
      withNeo4jSnaplet neo4j $ do
        relTypes <- Neo4j.allRelationshipTypes
        flip (maybe $ return ()) userId $ \userId' -> do
          mbZombieNode <- Neo4j.getNode $ T.encodeUtf8 $ Auth.unUid userId'
          flip (maybe $ return ()) mbZombieNode $ \zombieNode -> do
            rels <- Neo4j.getRelationships zombieNode Neo4j.Any relTypes
            mapM_ Neo4j.deleteRelationship rels
            Neo4j.deleteNode zombieNode

defaultNeo4jAuthPropNames :: PropertyNames
defaultNeo4jAuthPropNames = PropertyNames
  { labelUser = "User"
  , propLogin = "login"
  , propEmail = "email"
  , propPassword = "password"
  , propActivatedAt = "activatedAt"
  , propSuspendedAt = "suspendedAt"
  , propRememberToken = "rememberToken"
  , propLoginCount = "loginCount"
  , propFailedLoginCount = "failedLoginCount"
  , propLockedOutUntil = "lockedOutUntil"
  , propCurrentLoginAt = "currentLoginAt"
  , propLastLoginAt = "lastLoginAt"
  , propCurrentLoginIp = "currentLoginIp"
  , propLastLoginIp = "lastLoginIp"
  , propCreatedAt = "createdAt"
  , propUpdatedAt = "updatedAt"
  , propResetToken = "resetToken"
  , propResetRequestedAt = "resetRequestedAt"
  , propMeta = "meta"
  , relROLE = "ROLE"
  , labelRole = "Role"
  , propRole = "role"
  }

-- Convenience Functions

withNeo4jSnaplet :: Neo4jSnaplet -> Neo4j a -> IO a
withNeo4jSnaplet (Neo4jSnaplet hostname port) =
    Neo4j.withConnection hostname port

nodeToUserId :: Neo4j.Node -> Auth.UserId
nodeToUserId = Auth.UserId . T.decodeUtf8 . Neo4j.nodeId

nodeToAuthUser
  :: PropertyNames -> Neo4j.Node -> [Auth.Role] -> Maybe AuthUser
nodeToAuthUser (PropertyNames{..}) node roles = do
    login <- getTextProperty propLogin
    return AuthUser
      { userId = Just $ nodeToUserId node
      , userLogin = login
      , userEmail = getTextProperty propEmail
      , userPassword = Auth.Encrypted <$> getByteStringProperty propPassword
      , userActivatedAt = getTimeProperty propActivatedAt
      , userSuspendedAt = getTimeProperty propSuspendedAt
      , userRememberToken = getTextProperty propRememberToken
      , userLoginCount = getIntProperty propLoginCount
      , userFailedLoginCount = getIntProperty propFailedLoginCount
      , userLockedOutUntil = getTimeProperty propLockedOutUntil
      , userCurrentLoginAt = getTimeProperty propCurrentLoginAt
      , userLastLoginAt = getTimeProperty propLastLoginAt
      , userCurrentLoginIp = getByteStringProperty propCurrentLoginIp
      , userLastLoginIp = getByteStringProperty propLastLoginIp
      , userCreatedAt = getTimeProperty propCreatedAt
      , userUpdatedAt = getTimeProperty propUpdatedAt
      , userResetToken = getTextProperty propResetToken
      , userResetRequestedAt = getTimeProperty propResetRequestedAt
      , userRoles = roles
      , userMeta = maybe HM.empty id $ do
          jsonText <- getTextProperty propMeta
          Aeson.decode $ fromString $ T.unpack jsonText
      }
  where getProperty propertyName =
            HM.lookup propertyName $ Neo4j.getNodeProperties node
        getIntProperty propertyName = maybe 0 id $ do
            propertyValue <- getProperty propertyName
            case propertyValue of
              Neo4j.ValueProperty (Neo4j.IntVal i) -> Just $ fromIntegral i
              _ -> Nothing
        getTextProperty propertyName = do
            propertyValue <- getProperty propertyName
            case propertyValue of
              Neo4j.ValueProperty (Neo4j.TextVal t) -> Just t
              _ -> Nothing
        getTimeProperty propertyName = do
            timeString <- getTextProperty propertyName
            parseTime defaultTimeLocale iso8601Format $ T.unpack timeString
        getByteStringProperty propertyName = do
            propertyValue <- getProperty propertyName
            case propertyValue of
              Neo4j.ArrayProperty rawValues ->
                  fmap BS.pack $ sequence $ map getWord8 rawValues
              _ -> Nothing
          where getWord8 :: Neo4j.Val -> Maybe Word8
                getWord8 (Neo4j.IntVal i64) =
                    if i64 < 256 then Just $ fromIntegral i64 else Nothing
                getWord8 _ = Nothing

authUserToProps :: PropertyNames -> AuthUser -> IO Neo4j.Properties
authUserToProps (PropertyNames{..}) (AuthUser{..}) = do
    password <- case userPassword of
      Nothing -> return Nothing
      Just (Auth.Encrypted password) -> return $ Just password
      Just (Auth.ClearText password) -> Just <$> Auth.encrypt password
    return $ foldl' (flip ($)) HM.empty $
      [ addTextProperty propLogin userLogin
      , might (addTextProperty propEmail) userEmail
      , might (addByteStringProperty propPassword) password
      , might (addTimeProperty propActivatedAt) userActivatedAt
      , might (addTimeProperty propSuspendedAt) userSuspendedAt
      , might (addTextProperty propRememberToken) userRememberToken
      , addIntProperty propLoginCount userLoginCount
      , addIntProperty propFailedLoginCount userFailedLoginCount
      , might (addTimeProperty propLockedOutUntil) userLockedOutUntil
      , might (addTimeProperty propCurrentLoginAt) userCurrentLoginAt
      , might (addTimeProperty propLastLoginAt) userLastLoginAt
      , might (addByteStringProperty propCurrentLoginIp) userCurrentLoginIp
      , might (addByteStringProperty propLastLoginIp) userLastLoginIp
      , might (addTimeProperty propCreatedAt) userCreatedAt
      , might (addTimeProperty propUpdatedAt) userUpdatedAt
      , might (addTextProperty propResetToken) userResetToken
      , might (addTimeProperty propResetRequestedAt) userResetRequestedAt
      , addTextProperty propMeta $ T.decodeUtf8 $ BS.concat $ BS.toChunks $
          Aeson.encode userMeta
      ]
  where might :: (a -> b -> b) -> Maybe a -> b -> b
        might = maybe id
        addIntProperty key =
            HM.insert key . Neo4j.ValueProperty . Neo4j.IntVal . fromIntegral
        addTextProperty key = HM.insert key . Neo4j.newval
        addTimeProperty key = addTextProperty key . T.pack .
                              formatTime defaultTimeLocale iso8601Format
        addByteStringProperty key =
            HM.insert key . Neo4j.newval .
            map (fromIntegral :: (Word8 -> Int64)) . BS.unpack

iso8601Format :: String
iso8601Format = iso8601DateFormat $ Just "%H:%M:%S,%QZ"

createIndexIfNeeded :: T.Text -> T.Text -> Neo4j ()
createIndexIfNeeded label propertyName = do
  propertyNames <- concatMap Neo4j.indexProperties <$> Neo4j.getIndexes label
  if propertyName `elem` propertyNames
    then return ()
    else Neo4j.createIndex label propertyName >> return ()

-- Queries

lookupByProperty
  :: (PropertyNames -> T.Text) -> Neo4jAuthManager -> T.Text
  -> IO (Maybe AuthUser)
lookupByProperty prop (Neo4jAuthManager neo4j
                       propertyNames@PropertyNames{labelUser}) value =
    withNeo4jSnaplet neo4j $ do
      nodes <- Neo4j.getNodesByLabelAndProperty labelUser $
          Just $ prop propertyNames |: value
      case nodes of
        [node] -> do
            roles <- getRolesForNode propertyNames node
            return $ nodeToAuthUser propertyNames node roles
        _ -> return Nothing

getRolesForNode :: PropertyNames -> Neo4j.Node -> Neo4j [Auth.Role]
getRolesForNode (PropertyNames{relROLE, propRole}) node = do
    rels <- Neo4j.getRelationships node Neo4j.Outgoing [relROLE] 
    fmap catMaybes $ forM rels $ \rel -> do
       roleNode <- Neo4j.getRelationshipTo rel
       roleProp <- Neo4j.getProperty roleNode propRole
       case roleProp of
         Just (Neo4j.ValueProperty (Neo4j.TextVal role)) ->
             return $ Just $ Auth.Role $ T.encodeUtf8 role
         _ -> return Nothing

connectNodeToRole
  :: PropertyNames -> Neo4j.Node -> Auth.Role -> Neo4j Neo4j.Node
connectNodeToRole (PropertyNames{relROLE, labelRole, propRole}) node
                  (Auth.Role txtRole) = do
    let role = T.decodeUtf8 txtRole
    roleNodes <- Neo4j.getNodesByLabelAndProperty labelRole $
        Just $ propRole |: role
    roleNode <- case roleNodes of
      roleNode:_ -> return roleNode
      [] -> Neo4j.createNode $ HM.fromList [(propRole |: role)]
    _ <- Neo4j.createRelationship relROLE HM.empty node roleNode
    return roleNode

syncRoles :: PropertyNames -> Neo4j.Node -> [Auth.Role] -> Neo4j ()
syncRoles (propertyNames@PropertyNames{relROLE, propRole})
          node roles = do
    let desiredRoles = Set.fromList $
            map (\(Auth.Role role) -> role) roles
    rels <- Neo4j.getRelationships node Neo4j.Outgoing [relROLE] 

    -- Look for undesired relationships 
    remainingRoles <- fmap (Set.fromList . catMaybes) $ forM rels $ \rel -> do
       roleNode <- Neo4j.getRelationshipTo rel
       mbRoleProp <- Neo4j.getProperty roleNode propRole
       case mbRoleProp of
         Just (Neo4j.ValueProperty (Neo4j.TextVal txtRole)) ->
           let role = T.encodeUtf8 txtRole in
           if role `Set.notMember` desiredRoles
             then do
               Neo4j.deleteRelationship rel
               return Nothing
             else return $ Just role
         _ -> return Nothing

    -- Add missing relationships.
    forM_ (map Auth.Role $ Set.toList $ desiredRoles Set.\\ remainingRoles) $
        connectNodeToRole propertyNames node 
    return ()
