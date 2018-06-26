module Tests.OIDC.Crypto.Jwt
    ( testTree
    ) where


import           Control.Lens     (view)
import           Crypto.JWT       (asPublicKey)
import           Data.Coerce      (coerce)
import           Data.Time        (addUTCTime, getCurrentTime)
import qualified Data.UUID.V4     as UUID
import           Test.Tasty
import           Test.Tasty.HUnit

import           OIDC.Crypto.Jwk  (generateEd25519)
import           OIDC.Crypto.Jwt  (newAccessToken, verifyAccessToken)
import           OIDC.Crypto.RNG  (newRNG)

import           OIDC.Types       (UserId (..))

import           Tests.Utils      (assertRight', assertRightM')

testTree :: TestTree
testTree = testGroup "Tests.OIDC.Crypto.Jwt"
    [ testJwtEncodeDecode
    ]


testJwtEncodeDecode :: TestTree
testJwtEncodeDecode = testCase "Sign/Verify" $ do
  rng <- newRNG

  key <- generateEd25519 rng
  pub <- case view asPublicKey key of
           Nothing -> assertFailure "Has public key"
           Just k -> pure k

  t0 <- getCurrentTime
  let
    t1 = addUTCTime 3600 t0
  uid <- coerce <$> UUID.nextRandom

  jwt <- assertRightM' "generates keys"
         $ newAccessToken key rng uid t1

  _ <- assertRight' "public verifies token" $ verifyAccessToken pub t0 jwt
  _ <- assertRight' "private verifies token" $ verifyAccessToken key t0 jwt

  case verifyAccessToken pub (addUTCTime 100 t1) jwt of
    Left _ -> pure ()
    Right _ -> assertFailure "expires"

  pure ()
