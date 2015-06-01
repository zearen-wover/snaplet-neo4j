module Snap.Snaplet.Auth.Backends.Neo4j.Types
  ( Neo4jAuthManager(..)
  , PropertyNames(..)
  ) where

import Data.Text as T

import Snap.Snaplet.Neo4j.Internal ( Neo4jSnaplet(..) )

data Neo4jAuthManager = Neo4jAuthManager
  { neo4jSnaplet :: Neo4jSnaplet
  , propertyNames :: PropertyNames
  }

data PropertyNames = PropertyNames
  { indexUser :: Maybe T.Text
  , propRole :: T.Text
  , propLogin :: T.Text
  , propEmail :: T.Text
  , propPassword :: T.Text
  , propActivatedAt :: T.Text
  , propSuspendedAt :: T.Text
  , propRememberToken :: T.Text
  , propLoginCount :: T.Text
  , propFailedLoginCount :: T.Text
  , propLockedOutUntil :: T.Text
  , propCurrentLoginAt :: T.Text
  , propLastLoginAt :: T.Text
  , propCurrentLoginIp :: T.Text
  , propLastLoginIp :: T.Text
  , propCreatedAt :: T.Text
  , propUpdatedAt :: T.Text
  , propResetToken :: T.Text
  , propResetRequestedAt :: T.Text
  , relROLE :: T.Text
  , indexRole :: Maybe T.Text
  , relMETA :: T.Text
  }

  
