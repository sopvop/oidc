{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TemplateHaskell            #-}

module OIDC.Web.Monad
  ( WebM(..)
  , runWebM
  , Web(..)
  , HasWeb(..)
  , initWeb
  , Redirect(..)
  , redirect
  , redirectForm
  ) where

import           Control.Lens (view)
import           Control.Lens.TH (makeClassy)
import           Control.Monad.Catch
    (Exception, MonadCatch, MonadMask, MonadThrow, throwM)
import           Control.Monad.IO.Class (MonadIO)
import           Control.Monad.Reader (MonadReader, ReaderT (..), runReaderT)
import           Data.ByteString (ByteString)
import           Network.HTTP.Types (Header, Status, hLocation, seeOther303)

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
           , MonadIO, MonadReader Web
           , MonadThrow, MonadCatch, MonadMask )


runWebM
  :: Web
  -> WebM a
  -> IO a
runWebM env act = runReaderT (unWebM act) env


instance HasUserStore WebM where
  askUserStore = view userStore


data Redirect = Redirect Status [Header]
  deriving (Show)

instance Exception Redirect where


redirect
  :: MonadThrow m
  => Status
  -> [Header]
  -> ByteString
  -> m a
redirect s h url =
  throwM $ Redirect s ((hLocation, url):h)

redirectForm
  :: MonadThrow m
  => [Header]
  -> ByteString
  -> m ()
redirectForm h url =
  throwM $ Redirect seeOther303 ((hLocation, url):h)

