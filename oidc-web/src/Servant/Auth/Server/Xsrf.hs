{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE GADTs                 #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings     #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE TypeOperators         #-}
{-# LANGUAGE UndecidableInstances  #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module Servant.Auth.Server.Xsrf
   ( XsrfCookie
  , XsrfSettings(..)
  ) where

import           Control.Monad.IO.Class (liftIO)
import           Data.ByteString (ByteString)
import           Data.Text (Text)
import qualified Data.Text.Encoding as Text
import           Network.Wai (Request, requestHeaders)
import           Web.Cookie

import           Network.HTTP.Types (hCookie)

import           Servant
    ((:>), Handler, HasContextEntry (getContextEntry), HasServer (..),
    Proxy (..))
import           Servant.Auth.Server.Internal.AddSetCookie
    (AddSetCookies, AddSetCookiesApi, Nat (..), SetCookieList (..),
    addSetCookies)
import           Servant.Server.Internal.RoutingApplication


import           Servant.API.Auth.Xsrf

import           OIDC.Crypto.Message



data XsrfSettings = XsrfSettings
  { xsrfGenerateToken :: IO ByteString -- ASCII
  , xsrfEncryptToken  :: ByteString -> IO UrlEncoded
  , xsrfDecodeToken   :: UrlEncoded -> IO (Maybe ByteString)
  , xsrfCookieSecure  :: Bool
  }



instance ( n ~ 'S 'Z
         , HasServer (AddSetCookiesApi n api) ctxs
         , HasServer api ctxs -- this constraint is needed to implement hoistServer
         , AddSetCookies n (ServerT api Handler) (ServerT (AddSetCookiesApi n api) Handler)
         , HasContextEntry ctxs XsrfSettings
         ) => HasServer (XsrfCookie :> api) ctxs where
  type ServerT (XsrfCookie :> api) m =
    Text -> ServerT api m

  hoistServerWithContext _ pc nt s =
    hoistServerWithContext (Proxy :: Proxy api) pc nt . s

  route _ context subserver =
    route (Proxy :: Proxy (AddSetCookiesApi n api))
          context
          (fmap go subserver `addAuthCheck` authCheck)

    where
      authCheck :: DelayedIO (Text, SetCookieList ('S 'Z))
      authCheck = withRequest $ \req -> liftIO $ do
        xsrf <- maybe (xsrfGenerateToken xsrfSettings) pure
               =<< readXsrfCookie xsrfSettings req
        newCookie <- makeXsrfCookie xsrfSettings xsrf
        let cookies = Just newCookie `SetCookieCons` SetCookieNil
        return (Text.decodeLatin1 xsrf, cookies)

      xsrfSettings :: XsrfSettings
      xsrfSettings = getContextEntry context

      go :: ( old ~ ServerT api Handler
            , new ~ ServerT (AddSetCookiesApi n api) Handler
            )
         => (Text -> ServerT api Handler)
         -> (Text, SetCookieList n) -> new
      go fn (authResult, cookies) = addSetCookies cookies $ fn authResult


readXsrfCookie
  :: XsrfSettings
  -> Request
  -> IO (Maybe ByteString)
readXsrfCookie settings req =
  case mtok of
    Nothing -> pure Nothing
    Just t -> xsrfDecodeToken settings (UrlEncoded t)
  --let cookies = parseCookies cookies'
  where
    mtok = lookup "CSRF-TOKEN" $ foldr gatherCookies [] $ requestHeaders req
    gatherCookies (n,h) acc
       | n == hCookie = acc ++ parseCookies h
       | otherwise = acc

makeXsrfCookie
  :: XsrfSettings
  -> ByteString
  -> IO SetCookie
makeXsrfCookie settings value = do
  UrlEncoded encrypted <- xsrfEncryptToken settings value
  pure $ defaultSetCookie
    { setCookieName = "CSRF-TOKEN"
    , setCookieValue = encrypted
    , setCookieSecure = xsrfCookieSecure settings
    , setCookieHttpOnly = True
    , setCookieSameSite = Just sameSiteLax
    , setCookieMaxAge = Just 3600
    , setCookieExpires = Nothing
    , setCookiePath = Just "/"
    , setCookieDomain = Nothing -- TODO: Or should we set it?
    }
