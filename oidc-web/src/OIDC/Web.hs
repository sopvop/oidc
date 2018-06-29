{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeOperators     #-}
module OIDC.Web
  ( application
  ) where

import           Control.Exception (catch)
import           Control.Lens ((^.))
import           Control.Monad.Except (ExceptT (..))
import           Data.ByteString.Builder (byteStringHex, toLazyByteString)
import qualified Data.ByteString.Char8 as BSC
import           Data.ByteString.Lazy (toStrict)

import           Data.Proxy (Proxy (..))
import           Data.Time (addUTCTime, getCurrentTime)
import           Network.HTTP.Types (Status (..))

import           Servant.API ((:<|>) (..), (:>), Raw)
import           Servant.Auth.Server.SetCookieOrphan ()
import           Servant.Server
    (Application, Context (..), Handler (..), ServantErr (..),
    hoistServerWithContext, serveWithContext)
import           Servant.Server.Auth.Xsrf (XsrfSettings (..))
import           Servant.Utils.StaticFiles (serveDirectoryWebApp)

import           OIDC.Crypto.Message
    (SymKey (..), decryptExpiringPayload, encryptExpiringPayload)
import           OIDC.Crypto.RNG (RNG, newRNG, randomBytes)
import           OIDC.Web.Handlers (handlers)
import           OIDC.Web.Monad (HasWeb (..), Redirect (..), Web, runWebM)
import           OIDC.Web.Routes (Routes)


routes :: Proxy Routes
routes = Proxy

context :: Proxy '[XsrfSettings]
context = Proxy

api :: Proxy (Routes :<|> ("static" :> Raw))
api = Proxy

application :: Web -> IO Application
application env = do
  rng <- newRNG
  xsrf <- mkXsrfSettings rng
  let ctx = xsrf :. EmptyContext
  pure . serveWithContext api ctx $
       hoistServerWithContext routes context liftWebM handlers
       :<|> static
  where
    liftWebM act = Handler . ExceptT . catchRedirect $ runWebM env act
    static = serveDirectoryWebApp (env^.staticDirectory)

    catchRedirect act = catch (Right <$> act) $ \(Redirect status headers) -> do
      let
        code = statusCode status
        msg = BSC.unpack $ statusMessage status
      pure $ Left (ServantErr code msg mempty headers)


mkXsrfSettings :: RNG -> IO XsrfSettings
mkXsrfSettings rng = do
  key <- SymKey <$> randomBytes 32 rng
  let
    encrypt msg = do
      t <- getCurrentTime
      let expire = addUTCTime 3600 t
      encryptExpiringPayload key rng msg expire
    decrypt msg =
      decryptExpiringPayload key msg <$> getCurrentTime
    generate = toStrict . toLazyByteString . byteStringHex
      <$> randomBytes 16 rng
  pure $ XsrfSettings generate encrypt decrypt

