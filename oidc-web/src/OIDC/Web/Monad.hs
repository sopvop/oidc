{-# LANGUAGE BangPatterns               #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE RankNTypes                 #-}
{-# LANGUAGE TemplateHaskell            #-}

module OIDC.Web.Monad
  ( WebM(..)
  , runWebM
  , Web(..)
  , HasWeb(..)
  , Environment(..)
  , initWeb
  , sessionCookieSettings
  , jwtSettings
  , Redirect(..)
  , redirect
  , redirectForm
  , WebCrypto(..)
  , wcNewRememberToken
  , initWebCrypto
  , newKey
  , HasWebCrypto(..)
  , withWebCrypto
  , newRememberToken
  , generateToken
  , encryptMessage
  , decryptMessage
  , mkRememberCookieHeader
  , mkSessionCookieHeader
  ) where

import           Codec.Serialise (Serialise)

import           Control.Lens (view)
import           Control.Lens.TH (makeClassy)
import           Control.Monad.Catch
    (Exception, MonadCatch, MonadMask, MonadThrow, throwM)
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Control.Monad.Reader
    (MonadReader, ReaderT (..), ask, runReaderT)
import qualified Crypto.JOSE.JWK as JWK
import           Crypto.JOSE.Types (Base64Octets (..))
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Builder as BL
import qualified Data.ByteString.Lazy as BSL
import qualified Data.ByteString.Short as SBS
import           Data.Time (UTCTime, getCurrentTime)
import qualified Data.UUID.Types as UUID
import           Network.HTTP.Types (Header, Status, hLocation, seeOther303)
import           Web.Cookie
    (SetCookie, defaultSetCookie, renderSetCookie, sameSiteLax,
    setCookieHttpOnly, setCookieMaxAge, setCookieName, setCookiePath,
    setCookieSameSite, setCookieSecure, setCookieValue)

import           Crypto.JWT (JWK)

import           Servant.Auth.Server
    (CookieSettings (..), IsSecure (..), JWTSettings, defaultCookieSettings,
    defaultJWTSettings, makeSessionCookie)

import           OIDC.Crypto.Message
    (SymKey (..), decryptExpiringPayload, encryptExpiringPayload)
import           OIDC.Crypto.Message (UrlEncoded (..))
import           OIDC.Crypto.RNG (newRNG, randomBytes)
import           OIDC.Server.UserStore
    (HasUserStore (..), RememberToken (..), UserStore (..))
import           OIDC.Types (UserAuth (..), UserId (..))

import           OIDC.Web.Routes (UserIdClaim (..))

data Environment
  = TestingEnvironment
  | ProductionEnvironment
  deriving(Eq,Ord,Show)

data Web = Web
  { _environment     :: Environment
  , _userStore       :: UserStore
  , _webCrypto       :: WebCrypto
  , _staticDirectory :: FilePath
  , _jwtSigningKey   :: JWK
  }

initWeb
  :: Environment
  -> FilePath
  -> UserStore
  -> WebCrypto
  -> JWK
  -> IO Web
initWeb e p s w k = pure $ Web e s w p k

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
  -> m a
redirectForm h url =
  throwM $ Redirect seeOther303 ((hLocation, url):h)


sessionCookieSettings
  :: Web
  -> CookieSettings
sessionCookieSettings env =
  defaultCookieSettings
  { cookieIsSecure =  secure
  , cookieXsrfSetting = Nothing }
  where
    !secure = if _environment env /= TestingEnvironment
             then Secure
             else NotSecure

jwtSettings
  :: Web
  -> JWTSettings
jwtSettings = defaultJWTSettings . _jwtSigningKey

mkSessionCookieHeader
  :: UserAuth
  -> WebM (Maybe Header)
mkSessionCookieHeader usr = do
  env <- ask
  let
    cs = sessionCookieSettings env
    js = jwtSettings env
  fmap (fmap renderSetCookieHeader)
    . liftIO . makeSessionCookie cs js
    $ UserIdClaim (userId usr) "foo.bar.com"

mkRememberCookieHeader
  :: UserId
  -> RememberToken
  -> WebM Header
mkRememberCookieHeader (UserId uid) (RememberToken token) = do
    env <- ask
    msg <- liftIO $ wcEncryptMessage (_webCrypto env)
           (UUID.toByteString uid, token)
           =<< getCurrentTime
    let
      cookie =
        defaultSetCookie
        { setCookieName = "rememberme"
        , setCookiePath = Just "/"
        , setCookieValue =  unUrlEncoded msg
        , setCookieMaxAge = Just $ 3600*24*14
        , setCookieHttpOnly= True
        , setCookieSecure  = _environment env /= TestingEnvironment
        , setCookieSameSite = Just sameSiteLax
        }
    pure $ renderSetCookieHeader cookie

renderSetCookieHeader
  :: SetCookie
  -> Header
renderSetCookieHeader c = ( "Set-Cookie", value )
  where
    !value = BSL.toStrict . BL.toLazyByteString $ renderSetCookie c


data WebCrypto = WebCrypto
  { wcGenerateToken
    :: Int
    -> IO BS.ByteString
  , wcEncryptMessage
    :: forall a
    . Serialise a
    => a
    -> UTCTime
    -> IO UrlEncoded
  , wcDecryptMessage
    :: forall a
    . Serialise a
    => UrlEncoded
    -> UTCTime
    -> IO (Maybe a)
  }

class MonadIO m => HasWebCrypto m where
  getWebCrypto :: m WebCrypto

withWebCrypto
  :: HasWebCrypto m
  => (WebCrypto -> m b)
  -> m b
withWebCrypto act = getWebCrypto >>= act

generateToken :: HasWebCrypto m => Int -> m BS.ByteString
generateToken len = withWebCrypto $ \wc ->
  liftIO $ wcGenerateToken wc len

wcNewRememberToken
  :: WebCrypto
  -> IO RememberToken
wcNewRememberToken wc =
  RememberToken . SBS.toShort <$> wcGenerateToken wc 16

newRememberToken
  :: HasWebCrypto m
  => m RememberToken
newRememberToken = withWebCrypto $ liftIO . wcNewRememberToken


encryptMessage
  :: HasWebCrypto m
  => Serialise a
  => a
  -> UTCTime
  -> m UrlEncoded
encryptMessage msg t = withWebCrypto $ \wc ->
  liftIO $ wcEncryptMessage wc msg t

decryptMessage
  :: HasWebCrypto m
  => Serialise a
  => UrlEncoded
  -> UTCTime
  -> m (Maybe a)
decryptMessage msg t = withWebCrypto $ \wc ->
  liftIO $ wcDecryptMessage wc msg t

makeClassy ''Web

instance HasUserStore WebM where
  askUserStore = view userStore

instance HasWebCrypto WebM where
  getWebCrypto = view webCrypto

initWebCrypto :: JWK.JWK -> IO WebCrypto
initWebCrypto key = do
  rng <- newRNG

  let
    keyBS = case view JWK.jwkMaterial key of
      JWK.OctKeyMaterial (JWK.OctKeyParameters (Base64Octets t)) -> Just t
      _ -> Nothing

  symkey <- case keyBS of
    Nothing -> error "Bad key" -- TODO: error msg?
    Just bs -> if BS.length bs /= 32
               then error "Key bad length"
               else pure (SymKey bs)

  let
    newToken i = randomBytes i rng

  pure $ WebCrypto newToken
    (encryptExpiringPayload symkey rng)
    (\u -> pure . decryptExpiringPayload symkey u)

newKey :: IO JWK.JWK
newKey = JWK.genJWK $ JWK.OctGenParam 32
