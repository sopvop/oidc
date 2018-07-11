{-# LANGUAGE DataKinds             #-}
{-# LANGUAGE FlexibleContexts      #-}
{-# LANGUAGE FlexibleInstances     #-}
{-# LANGUAGE GADTs                 #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables   #-}
{-# LANGUAGE TypeFamilies          #-}
{-# LANGUAGE TypeOperators         #-}
{-# LANGUAGE UndecidableInstances  #-}
module Servant.Auth.Server.Remember
  ( Remember
  , RememberSettings(..)
  ) where


import           Control.Monad (join)
import           Data.ByteString (ByteString)
import           Data.Traversable (for)
import           Network.Wai (requestHeaders)
import           Web.Cookie

import           Network.HTTP.Types (hCookie)

import           Servant.Auth.Server.Internal.Class (IsAuth (..))
import           Servant.Auth.Server.Internal.Types
    (AuthCheck (..), AuthResult (..))

import           OIDC.Crypto.Message (UrlEncoded (..))

data Remember a

data RememberSettings a = RememberSettings
  { rememberAuth       :: UrlEncoded -> IO (Maybe a)
  , rememberCookieName :: ByteString
  }

instance IsAuth (Remember a) a where
  type AuthArgs (Remember a) = '[RememberSettings a]
  runAuth _ _ settings = AuthCheck check
    where
      check req = do
        let
          mtok = lookup name
                 . foldr gatherCookies []
                 $ requestHeaders req
        auth <- for mtok $ rememberAuth settings . UrlEncoded

        case join auth of
          Nothing -> pure Indefinite
          Just v -> pure $ Authenticated v


      name = rememberCookieName settings
      gatherCookies (n,h) acc
        | n == hCookie = acc ++ parseCookies h
        | otherwise = acc

