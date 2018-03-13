{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings          #-}
module OIDC.Crypto.Jwt
    ( newToken
    , verifyToken
    , newAccessToken
    , verifyAccessToken
    , toUserIdSub
    , fromUserIdSub
    , encodeAccessToken
    , decodeAccessToken
    ) where

import           Control.Error              (note)
import           Control.Lens
    (Prism', coerced, preview, prism, review, (&), (.~), (?~), (^.))
import           Control.Monad.Except
    (Except, MonadError, runExcept, runExceptT)
import           Control.Monad.Time         (MonadTime (..))
import           Control.Monad.Trans.Reader (ReaderT, ask, runReaderT)
import           Crypto.JOSE.JWS            (Alg (EdDSA), newJWSHeader)
import           Crypto.JWT
    (ClaimsSet, Error, JWK, JWKStore, JWTError, JWTValidationSettings,
    NumericDate (..), SignedJWT, StringOrURI, algorithms, claimExp, claimIss,
    claimSub, decodeCompact, defaultJWTValidationSettings, emptyClaimsSet,
    encodeCompact, issuerPredicate, signClaims, string, verifyClaims)
import           Crypto.Random              (withDRG)
import           Data.Bifunctor             (first)
import qualified Data.ByteString.Lazy       as BL
import           Data.Coerce                (coerce)
import qualified Data.Set                   as Set
import           Data.Text                  (Text)
import qualified Data.Text                  as Text
import           Data.Time                  (UTCTime)
import qualified Data.UUID                  as UUID

import           OIDC.Crypto.RNG            (RNG, withRNG)
import           OIDC.Types
    (AccessToken (..), Base64Url (..), UserId (..))


newToken :: JWK -> RNG -> ClaimsSet -> IO (Either Error SignedJWT)
newToken key rnd claims = withRNG rnd $ \r ->
   withDRG r . runExceptT  $ signClaims key header claims
  where
   header = newJWSHeader ((), EdDSA)

newAccessToken :: JWK -> RNG -> UserId -> UTCTime -> IO (Either Error SignedJWT)
newAccessToken key rnd user t = newToken key rnd claims
  where
   claims = emptyClaimsSet
            & claimIss ?~ "oauth.example.com"
            & claimSub ?~ toUserIdSub user
            & claimExp ?~ NumericDate t


toUserIdSub :: UserId -> StringOrURI
toUserIdSub = review userSub

fromUserIdSub :: StringOrURI -> Maybe UserId
fromUserIdSub = preview userSub

userSub :: Prism' StringOrURI UserId
userSub = string . prism UUID.toString fr . coerced
  where
   fr s = note s (UUID.fromString s)
{-# INLINE userSub #-}

newtype VerifyM a = VerifyM (ReaderT UTCTime (Except JWTError) a)
    deriving (Functor, Applicative, Monad, MonadError JWTError)

-- | OH GOD WHY?
instance MonadTime VerifyM where
  currentTime = VerifyM ask

runVerifyM :: UTCTime -> VerifyM a -> Either JWTError a
runVerifyM t (VerifyM r) = runExcept (runReaderT r t)


verifyToken :: JWKStore k
              => k
              -> UTCTime
              -> JWTValidationSettings
              -> SignedJWT
              -> Either JWTError ClaimsSet
verifyToken key t validator jwt = runVerifyM t $
     verifyClaims val key jwt
  where
    val = validator
          & issuerPredicate .~ (== "oauth.example.com")
          & algorithms .~ Set.singleton EdDSA

verifyAccessToken :: JWKStore s => s -> UTCTime -> SignedJWT -> Either Text UserId
verifyAccessToken key t jwt = do
  claims <- first (Text.pack . show ) $ verifyToken key t validator jwt
  note "Can't parse sub uuid" $ fromUserIdSub =<< (claims^.claimSub)

  where
    validator = defaultJWTValidationSettings (const True)
                & issuerPredicate .~ (== "oauth.example.com")
                & algorithms .~ Set.singleton EdDSA

encodeAccessToken :: SignedJWT -> AccessToken
encodeAccessToken = coerce . BL.toStrict . encodeCompact

decodeAccessToken :: AccessToken -> Either JWTError SignedJWT
decodeAccessToken = decodeCompact . BL.fromStrict . coerce
