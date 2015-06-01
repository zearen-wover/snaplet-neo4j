{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
module Snap.Snaplet.Auth.Backends.Neo4j.Internal where

import Control.Monad ( sequence )
import Control.Monad.IO.Class ( liftIO )
import Data.Monoid ( mconcat, (<>) ) 
import Data.String ( fromString )
import System.IO ( FilePath )

import Data.Int ( Int64 )
import Data.List ( foldl' )
import Data.Time.Clock ( UTCTime )
import Data.Time.Format ( formatTime, parseTime )
import Data.Word ( Word8 )
import Database.Neo4j ( Neo4j, Hostname, Port )
import Database.Neo4j.Transactional.Cypher as Neo4j
import Snap.Snaplet ( Snaplet, SnapletInit, SnapletLens, makeSnaplet )
import Snap.Snaplet.Auth
    ( AuthFailure(..), AuthManager(..), AuthSettings(..), AuthUser(..)
    , IAuthBackend(..))
import Snap.Snaplet.Session ( SessionManager )
import Snap.Snaplet.Session.Common ( mkRNG )
import System.Locale ( defaultTimeLocale, iso8601DateFormat )
import Web.ClientSession ( getKey )

import qualified Data.Aeson as Aeson
import qualified Data.ByteString as BS
import qualified Data.ByteString.Lazy as BS (toChunks)
import qualified Data.HashMap.Strict as HM
import qualified Data.Text as T
import qualified Data.Text.Encoding as T ( decodeUtf8, encodeUtf8 )
import qualified Data.Text.Lazy as T ( toStrict )
import qualified Data.Text.Lazy.Builder as T ( fromText, toLazyText )
import qualified Database.Neo4j as Neo4j
import qualified Snap.Snaplet.Auth as Auth

import Snap.Snaplet.Neo4j.Internal ( Neo4jSnaplet(..) )
import Snap.Snaplet.Auth.Backends.Neo4j.Types (
    Neo4jAuthManager(..), PropertyNames(..) )

defaultNeo4jAuthPropNames :: PropertyNames
defaultNeo4jAuthPropNames = PropertyNames
  { indexUser = Just "User"
  , propRole = "role"
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
  , indexRole = Just "Role"
  }

mkNeo4jAuthManager :: Hostname -> Port -> PropertyNames -> Neo4jAuthManager
mkNeo4jAuthManager hostname port =
    Neo4jAuthManager $ Neo4jSnaplet hostname port

initNeo4jAuthManager ::
  AuthSettings ->
  SnapletLens b SessionManager ->
  Either Neo4jSnaplet (Hostname, Port) ->
  PropertyNames ->
  SnapletInit b (AuthManager b)
initNeo4jAuthManager (AuthSettings{..}) sessionManager neo4j propertyNames =
    makeSnaplet "neo4j-auth" "Provides authentification via Neo4j" Nothing
    $ liftIO $ do
      key  <- getKey asSiteKey
      rng  <- mkRNG
      return AuthManager
        { backend = flip Neo4jAuthManager propertyNames $ case neo4j of
            Left neo4jSnaplet -> neo4jSnaplet
            Right host_port -> uncurry Neo4jSnaplet host_port
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
  save (Neo4jAuthManager neo4j (PropertyNames{..})) (AuthUser{..}) =
      case userId of
        -- Create case
        Nothing -> return $ Left BackendError
        -- Modify case
        Just userId -> return $ Left BackendError
  lookupByUserId (Neo4jAuthManager neo4j _) userId = do
      withNeo4jSnaplet neo4j $ do
        return ()
      return Nothing
  lookupByLogin (Neo4jAuthManager neo4j _) login = do
      withNeo4jSnaplet neo4j $ do
        return ()
      return Nothing
  lookupByRememberToken (Neo4jAuthManager neo4j _) token = do
      withNeo4jSnaplet neo4j $ do
        return ()
      return Nothing
  destroy (Neo4jAuthManager neo4j _) authUser = return ()

-- Convenience Functions

withNeo4jSnaplet :: Neo4jSnaplet -> Neo4j a -> IO a
withNeo4jSnaplet (Neo4jSnaplet hostname port) =
    Neo4j.withConnection hostname port

propsToAuthUser :: PropertyNames -> Neo4j.Properties -> Maybe AuthUser
propsToAuthUser (PropertyNames{..}) properties = do
    login <- getTextProperty propLogin
    return AuthUser
      { userId = Nothing
      , userLogin = login
      , userEmail = getTextProperty propEmail
      , userPassword = fmap Auth.Encrypted $ getByteStringProperty propPassword
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
      , userRoles = []
      , userMeta = maybe HM.empty id $ do
          jsonText <- getTextProperty propMeta
          Aeson.decode $ fromString $ T.unpack jsonText
      }
  where getIntProperty propertyName = maybe 0 id $ do
            propertyValue <- HM.lookup propertyName properties
            case propertyValue of
              Neo4j.ValueProperty (Neo4j.IntVal i) -> Just $ fromIntegral i
              _ -> Nothing
        getTextProperty propertyName = do
            propertyValue <- HM.lookup propertyName properties
            case propertyValue of
              Neo4j.ValueProperty (Neo4j.TextVal t) -> Just t
              _ -> Nothing
        getTimeProperty propertyName = do
            timeString <- getTextProperty propertyName
            parseTime defaultTimeLocale iso8601Format $ T.unpack timeString
        getByteStringProperty propertyName = do
            propertyValue <- HM.lookup propertyName properties
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
      Just (Auth.ClearText password) -> fmap Just $ Auth.encrypt password
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
      , addTextProperty propMeta $ T.decodeUtf8 $ BS.concat $ BS.toChunks
          $ Aeson.encode userMeta
      ]
  where might :: (a -> b -> b) -> Maybe a -> b -> b
        might = maybe id
        addIntProperty key =
            HM.insert key . Neo4j.ValueProperty . Neo4j.IntVal . fromIntegral
        addTextProperty key = HM.insert key . Neo4j.ValueProperty . Neo4j.TextVal
        addTimeProperty key = addTextProperty key . T.pack
                              . formatTime defaultTimeLocale iso8601Format
        addByteStringProperty key =
          HM.insert key . Neo4j.ArrayProperty
          . map (Neo4j.IntVal . fromIntegral) . BS.unpack

iso8601Format :: String
iso8601Format = iso8601DateFormat $ Just "%H:%M:%S,%QZ"

-- Queries

queryLookupByProperty
  :: (PropertyNames -> T.Text) -> PropertyNames-> T.Text
  -> (T.Text, Neo4j.Params)
queryLookupByProperty prop (propertyNames@PropertyNames{indexUser}) login =
    ( T.toStrict $ T.toLazyText $ mconcat
      [ "MATCH (u", maybe "" ((":"<>) . T.fromText) indexUser, "{"
      , T.fromText $ prop propertyNames, ":{", T.fromText paramProp
      , "}}) RETURN u;"]
    , HM.fromList [(paramProp, Neo4j.newparam login)]
    )
  where paramProp = "prop" :: T.Text
