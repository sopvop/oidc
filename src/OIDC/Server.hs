{-# LANGUAGE BangPatterns     #-}
{-# LANGUAGE FlexibleContexts #-}
module OIDC.Server
    (
    ) where

import           Control.Error
    (ExceptT (..), note, runExceptT, throwE)
import           Control.Exception         (Exception)
import           Control.Monad.Catch       (throwM)
import           Control.Monad.Trans.Class (lift)
import           Data.Bifunctor            (first)
import qualified Data.ByteString.Lazy      as BL
import           Data.Time                 (UTCTime)
import           Network.HTTP.Types.Status (status200)
import           Network.Wai
    (Application, Request, rawQueryString, responseLBS)
import           Web.FormUrlEncoded        (urlDecodeAsForm)

import           OIDC.Backend.Class        (UserStore (..))
import           OIDC.Crypto.Password      (verifyPassword)
import           OIDC.Types

tokenEndpoint :: Application
tokenEndpoint req respond = do

   respond $ responseLBS status200 mempty mempty



type Error = String

--passwordAuth :: Request -> IO (Either TokenRequestError TokenResponse)
passwordAuth req = runExceptT $ do
    r <- case  decoded of
      Left _ -> throwE TokenInvalidRequest
      Right !r -> pure r
    user <- ExceptT $ note TokenInvalidGrant
            <$> lookupUserByUsername (pgrUsername r)
    unless (verifyPassword (pgrPassword r) (userPassword user))
         $ throwE TokenInvalidGrant
    pure ()
  where
    decoded = urlDecodeAsForm (BL.fromStrict $ rawQueryString req)
    notFound = TokenInvalidGrant
