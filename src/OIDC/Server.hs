{-# LANGUAGE BangPatterns      #-}
{-# LANGUAGE FlexibleContexts  #-}
{-# LANGUAGE MultiWayIf        #-}
{-# LANGUAGE OverloadedStrings #-}
module OIDC.Server
    ( runTokenEndpoint
    , tokenEndpoint
    ) where

import           Control.Applicative             (Alternative, empty, (<|>))
import           Control.Error
    (ExceptT (..), hoistEither, hush, note, noteT, runExceptT, throwE)
import           Control.Exception               (Exception)
import           Control.Lens                    (both, to)
import           Control.Monad                   (unless, (<=<))
import           Control.Monad.Catch             (throwM)
import           Control.Monad.IO.Class          (MonadIO, liftIO)
import           Control.Monad.Reader            (ask)
import           Control.Monad.Trans.Class       (lift)
import           Control.Monad.Trans.Maybe       (MaybeT (..), runMaybeT)
import qualified Crypto.JWT                      as JWT
import qualified Data.Aeson                      as J
import           Data.Bifunctor                  (first)
import qualified Data.ByteString.Char8           as BS
import qualified Data.ByteString.Lazy            as BL
import           Data.Coerce                     (coerce)
import           Data.Maybe                      (fromMaybe)
import           Data.Semigroup                  ((<>))
import           Data.Text                       (Text)
import qualified Data.Text.Encoding              as Text
import           Data.Time                       (UTCTime, getCurrentTime)
import           Katip
    (Severity (..), logF, logMsg, ls, showLS, sl)
import           Network.HTTP.Media              (MediaType, mapContent, (//))
import           Network.HTTP.Types
    (Header, Status, badRequest400, hAuthorization, hCacheControl,
    hContentType, methodNotAllowed405, methodPost, ok200,
    requestEntityTooLarge413, unsupportedMediaType415)
import           Network.Wai
    (Application, Request, RequestBodyLength (ChunkedBody, KnownLength),
    Response, ResponseReceived, rawQueryString, requestBody, requestBodyLength,
    requestHeaders, requestMethod, responseLBS)
import           Network.Wai.Middleware.HttpAuth (extractBasicAuth)
import           OIDC.Crypto.Jwt
    (encodeAccessToken, newAccessToken)
import           OIDC.Crypto.Message             (encryptMessage)
import           OIDC.Crypto.Password            (verifyPassword)
import           OIDC.Server.Types
import           OIDC.Types
import           Web.FormUrlEncoded
    (Form, FromForm, fromForm, lookupMaybe, lookupUnique, urlDecodeForm)

runTokenEndpoint :: OidcEnv -> Application
runTokenEndpoint env req response = do
  r <- runServerM (tokenEndpoint req) env
  response r


--tokenEndpoint :: Application
tokenEndpoint :: Request -> ServerM Response
tokenEndpoint req  =
  if requestMethod req /= methodPost
  then
    pure (methodNotAllowed [methodPost])
  else runEndpoint . runExceptT $ do
    unless (requestIsFormUrlEncoded req)
           $  throwE badContent
    body <- ExceptT . liftIO $ readFormBody req
    runGrant $ do
      usr <- authorizeGrant req body
      t <- mkAccessTokenResponse usr
      pure $ responseLBS ok200 tokenHeaders $ J.encode t
  where
    badContent = HttpError unsupportedMediaType415
                 (TokenInvalidRequest !: "Invalid content-type")

authorizeGrant :: Request
               -> Form
               -> ExceptT (Ann TokenRequestError) ServerM UserAuth
authorizeGrant req body = do
  grantType <- hoistEither (parseGrantType body)
  case grantType of
    PasswordGrant ->
      authenticateClient req body
      *> parseBody body
      >>= passwordAuth
    _ -> throwAnn TokenUnsupportedGrantType "Unsupported grant type"


tokenHeaders :: [Header]
tokenHeaders =
   [( hContentType, "application/json;charset=UTF-8")
   ,( hCacheControl, "no-store")
   ,( "Pragma", "no-cache")]

runEndpoint :: Monad m
            => m (Either (HttpError (Ann e)) Response)
            -> m Response
runEndpoint act = do
  res <- act
  case res of
    Left e -> undefined -- TODO: error response
    Right r -> pure r

runGrant :: Functor m => ExceptT e m a -> ExceptT (HttpError e) m a
runGrant (ExceptT act) = ExceptT $ first f <$> act
  where
   f = HttpError badRequest400


parseBody :: (FromForm a, Monad m)
          => Form -> ExceptT (Ann TokenRequestError) m a
parseBody body = case fromForm body of
   Left _ -> throwAnn TokenInvalidRequest "Invalid parameters"
   Right !r -> pure r
{-# INLINEABLE parseBody #-}

passwordAuth :: PasswordGrantRequest
             -> ExceptT (Ann TokenRequestError) ServerM UserAuth
passwordAuth r = do
    user <- ExceptT $ note notFound
            <$> lookupUserByUsername (pgrUsername r)
    unless (verifyPassword (pgrPassword r) (userPassword user))
         $ throwE notFound
    pure user
  where
    notFound = Ann TokenInvalidGrant
               "User and password combination not found"

mkAccessTokenResponse :: UserAuth
                      -> ExceptT (Ann TokenRequestError) ServerM AccessTokenResponse
mkAccessTokenResponse usr = do
  t <- do
    t <- lift (generateAccessToken (userId usr))
    either badGenerate (pure . encodeAccessToken) t
  logF (sl "user_id" (userId usr)) mempty NoticeS "Granted new access token"
  pure $ AccessTokenResponse t "bearer" Nothing Nothing Nothing
  where
   badGenerate e = do
     logMsg mempty AlertS $
         "Can't generate access token" <> showLS e
     throwAnn TokenServerError "Internal error"

generateAccessToken :: UserId -> ServerM (Either JWT.Error JWT.SignedJWT)
generateAccessToken uid = do
  OidcEnv{oidcRNG=rng, oidcKeys=keys} <- ask
  liftIO $ do
    t <- getCurrentTime
    key <- storeAccessTokenSigningKey keys
    liftIO $ newAccessToken key rng uid t


methodNotAllowed :: [BS.ByteString] -> Response
methodNotAllowed allowed =
   responseLBS methodNotAllowed405 [("Allow", allowedBS)] mempty
  where
   allowedBS = BS.intercalate "," allowed

readBody :: Request -> IO (Maybe BL.ByteString)
readBody req = runMaybeT $ case len of
    ChunkedBody -> go
    KnownLength l | l > maxLength -> empty
                  | otherwise -> go
  where
    next = requestBody req
    len = requestBodyLength req
    go = loop 0 []
    loop sz acc = do
      chunk <- lift next
      let chunkLength = fromIntegral (BS.length chunk)
          accLength = sz + chunkLength
      if | chunkLength == 0 -> pure $! BL.fromChunks $ reverse acc
         | accLength > maxLength -> empty
         | otherwise -> loop accLength (chunk : acc)
    maxLength = 10240

readFormBody :: Request -> IO (Either (HttpError (Ann TokenRequestError)) Form)
readFormBody req = runExceptT $ do
  body <- noteT tooLarge . MaybeT $ readBody req
  case urlDecodeForm body of
    Left _ -> throwE badDecode
    Right !r -> pure r
  where
    tooLarge = HttpError requestEntityTooLarge413
      $ TokenInvalidRequest !: "Request body too large"
    badDecode = HttpError badRequest400
      $ TokenInvalidRequest
      !: "Error decoding x-www-form-urlencoded data from body"

data ClientCreds = ClientCreds
    { clientCredsId     :: ClientId
    , clientCredsSecret :: Maybe CleartextPassword
    }

onNothing :: Applicative f => Maybe a -> f a -> f a
onNothing act elseAct = maybe elseAct pure act

onNothingM :: Monad m => m (Maybe b) -> m b -> m b
onNothingM act elseAct = maybe elseAct pure =<< act

readClientCreds :: Request -> Form -> Maybe ClientCreds
readClientCreds req form = do
    (cid, pass) <- basic <|> hush fromForm
    pure $ ClientCreds (coerce cid) (coerce pass)
  where
    basic = do
      (a,b) <- extractBasicAuth <=< lookup hAuthorization
               $ requestHeaders req
      let pass = if BS.null b
                 then Nothing
                 else Just (Text.decodeLatin1 b)
      pure (Text.decodeLatin1 a, pass)
    fromForm =
        (,) <$> lookupUnique "client_id" form
            <*> lookupMaybe "client_secret" form

authenticateClient req form = do
  ClientCreds cid _ <-
    readClientCreds req form
    `onNothing`
    throwAnn TokenUnauthorizedClient "client_id is required"
  client <-
    lift (lookupClientById cid)
    `onNothingM`
    throwAnn TokenUnauthorizedClient "Unknown client"
  pure client

authenticateClientWithSecret :: Request
                             -> Form
                             -> ExceptT (Ann TokenRequestError) ServerM ClientAuth
authenticateClientWithSecret req form = do
  ClientCreds cid secret <-
    readClientCreds req form
    `onNothing`
    throwAnn TokenUnauthorizedClient "client_id is required"
  cleartext <- secret `onNothing`
    throwAnn TokenUnauthorizedClient  "client_secret required"

  client <-
    lift (lookupClientById cid)
    `onNothingM`
    throwAnn TokenUnauthorizedClient "client_id and password mismatch"

  pass <- clientSecret client `onNothing`
    throwAnn TokenInvalidGrant "Registered client does not support this grant"

  unless (verifyPassword  cleartext pass)
    $ throwAnn TokenUnauthorizedClient  "client_id and password mismatch"
  pure client

requestContentType :: Request -> BS.ByteString
requestContentType req =
  fromMaybe "application/octet-stream"
     $ lookup hContentType (requestHeaders req)

formUrlEncodedMedia :: MediaType
formUrlEncodedMedia = "application" // "x-www-form-urlencoded"

requestIsFormUrlEncoded :: Request -> Bool
requestIsFormUrlEncoded req =
    fromMaybe False
    . mapContent [(formUrlEncodedMedia, True)]
    $ requestContentType req

parseGrantType :: Form -> Either (Ann TokenRequestError) GrantType
parseGrantType f = do
  t <- first (const noGrant) $ lookupUnique "grant_type" f
  case t of
    "password" -> pure PasswordGrant
    _ -> Left unsupported
  where
    noGrant = TokenInvalidRequest !: "Parameter grant_type is required"
    unsupported = TokenInvalidGrant !: "Unsupported grant type"

data Ann e = Ann !e !Text

throwAnn :: Monad m => e -> Text -> ExceptT (Ann e) m a
throwAnn !e !t = throwE $! Ann e t

(!:) :: e -> Text -> Ann e
(!:) = Ann
infixr 5 !:

data HttpError e = HttpError
  { httpErrorStatus :: Status
  , httpError       :: e
  }
