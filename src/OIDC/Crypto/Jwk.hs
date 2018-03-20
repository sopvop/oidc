{-# LANGUAGE OverloadedStrings #-}
module OIDC.Crypto.Jwk
    ( generateKey
    , generateEd25519
    , PublicKeySet (..)
    , toPublicKeySet
    ) where

import           Control.Lens    (set, view)
import           Crypto.JWT
    (JWK, JWKSet (..), JWKStore, KeyMaterialGenParam (..), KeyUse (Sig),
    OKPCrv (Ed25519), asPublicKey, genJWK, jwkUse)
import           Data.Aeson      (ToJSON (..), object, pairs, (.=))
import           Data.Maybe      (mapMaybe)

import           OIDC.Crypto.RNG (RNG, runDRG)

generateKey :: RNG -> KeyMaterialGenParam -> IO JWK
generateKey r p = runDRG r (genJWK p)

generateEd25519 :: RNG -> IO JWK
generateEd25519 r = generateKey r (OKPGenParam Ed25519)

newtype PublicKeySet = PublicKeySet [JWK]

instance ToJSON PublicKeySet where
  toJSON (PublicKeySet keys) =
      object ["keys" .= keys ]
  toEncoding (PublicKeySet keys) =
      pairs $ "keys" .= keys

toPublicKeySet :: JWKSet -> PublicKeySet
toPublicKeySet (JWKSet keys) =
    PublicKeySet $ mapMaybe (fmap (set jwkUse (Just Sig)) . view asPublicKey) keys

