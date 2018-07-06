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

import           OIDC.Web.Handlers (handlers)
import           OIDC.Web.Monad
    (HasWeb (..), Redirect (..), Web (..), WebCrypto (..), runWebM)
import           OIDC.Web.Routes (Routes)


routes :: Proxy Routes
routes = Proxy

context :: Proxy '[XsrfSettings]
context = Proxy

api :: Proxy (Routes :<|> ("static" :> Raw))
api = Proxy

application :: Web -> IO Application
application env = do
  xsrf <- mkXsrfSettings env
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

mkXsrfSettings :: Web -> IO XsrfSettings
mkXsrfSettings w = do
  let
    wc = _webCrypto w
    encrypt msg = do
      t <- getCurrentTime
      let expire = addUTCTime 3600 t
      wcEncryptMessage wc msg expire
    decrypt msg =
      wcDecryptMessage wc msg =<< getCurrentTime
    generate = toStrict . toLazyByteString . byteStringHex
      <$> wcGenerateToken wc 16
  pure $ XsrfSettings generate encrypt decrypt

