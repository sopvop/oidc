{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TemplateHaskell            #-}

module OIDC.Web.Monad
  ( WebM(..)
  , runWebM
  , Web(..)
  , HasWeb(..)
  , initWeb
  ) where

import           Control.Lens (view)
import           Control.Lens.TH (makeClassy)
import           Control.Monad.IO.Class (MonadIO)
import           Control.Monad.Reader (MonadReader, ReaderT (..), runReaderT)

import           OIDC.Server.UserStore (HasUserStore (..), UserStore (..))

data Web = Web
  { _userStore       :: UserStore
  , _staticDirectory :: FilePath
  }

initWeb
  :: FilePath
  -> UserStore
  -> IO Web
initWeb p s = pure $ Web s p

makeClassy ''Web

newtype WebM a = WebM
  { unWebM :: ReaderT Web IO a }
  deriving ( Functor, Applicative, Monad
           , MonadIO, MonadReader Web)


runWebM
  :: Web
  -> WebM a
  -> IO a
runWebM env act = runReaderT (unWebM act) env


instance HasUserStore WebM where
  askUserStore = view userStore
