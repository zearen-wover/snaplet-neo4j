{-# LANGUAGE OverloadedStrings #-}
module Snap.Snaplet.Neo4j.Internal where

import Control.Monad.IO.Class (MonadIO, liftIO)

import Database.Neo4j ( Neo4j, Hostname, Port, withConnection )
import Snap.Snaplet ( SnapletInit, makeSnaplet )

data Neo4jSnaplet = Neo4jSnaplet
  { neo4jHostname :: Hostname
  , neo4jPort :: Port
  }

class MonadIO m => HasNeo4j m where
  getNeo4jSnaplet :: m Neo4jSnaplet

neo4jInit :: Hostname -> Port -> SnapletInit b Neo4jSnaplet
neo4jInit hostname port = makeSnaplet "neo4j" "Neo4j" Nothing $ do
    return $ Neo4jSnaplet hostname port

withNeo4j :: HasNeo4j m => Neo4j a -> m a
withNeo4j neo4j = getNeo4jSnaplet >>= flip withNeo4jSnaplet neo4j

withNeo4jSnaplet :: MonadIO m => Neo4jSnaplet -> Neo4j a -> m a
withNeo4jSnaplet (Neo4jSnaplet hostname port) =
    liftIO . withConnection hostname port
