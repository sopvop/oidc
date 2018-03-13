module OIDC.Crypto.Jwk
    ( generateKey
    , generateEd25519
    , PublicKeySet (..)
    , toPublicKeySet
    ) where

import           Control.Lens    (view)
import           Crypto.JWT
    (JWK, JWKSet (..), JWKStore, KeyMaterialGenParam (..), OKPCrv (Ed25519),
    asPublicKey, genJWK)
import           Data.Maybe      (mapMaybe)

import           OIDC.Crypto.RNG (RNG, runDRG)

generateKey :: RNG -> KeyMaterialGenParam -> IO JWK
generateKey r p = runDRG r (genJWK p)

generateEd25519 :: RNG -> IO JWK
generateEd25519 r = generateKey r (OKPGenParam Ed25519)

newtype PublicKeySet = PublicKeySet [JWK]

toPublicKeySet :: JWKSet -> PublicKeySet
toPublicKeySet (JWKSet keys) =
    PublicKeySet $ mapMaybe (view asPublicKey) keys

