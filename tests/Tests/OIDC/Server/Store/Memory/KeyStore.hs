module Tests.OIDC.Server.Store.Memory.KeyStore
    ( testTree
    ) where

import           Data.Time                         (addUTCTime, getCurrentTime)

import           Test.Tasty                        (TestTree, testGroup)
import           Test.Tasty.HUnit                  (assertEqual, testCase)

import           Crypto.JOSE.JWK                   (JWKSet (..))

import           OIDC.Crypto.Jwk                   (PublicKeySet (..))
import           OIDC.Crypto.Jwt
    (newAccessToken, verifyAccessToken)
import           OIDC.Crypto.RNG                   (newRNG)
import           OIDC.Server.Store.Memory.KeyStore (initMemoryKeyStore)
import           OIDC.Server.Types                 (KeyStore (..))
import           OIDC.Types.UserAuth               (newUserId)

import           Tests.Utils                       (assertRight', assertRightM')

testTree :: TestTree
testTree = testGroup "Tests.OIDC.Server.Store.Memory.KeyStore"
  [ basicTest
  ]

basicTest :: TestTree
basicTest = testCase "Basic" $ do
  ks <- initMemoryKeyStore 10000 Nothing

  rng <- newRNG

  t0 <- getCurrentTime

  jwk <- storeAccessTokenSigningKey ks
  PublicKeySet pubs <- storePublicKeys ks

  assertEqual "Adds public key" 1 (length pubs)

  uid <- newUserId

  let t1 = addUTCTime 3600 t0
  tok <- assertRightM' "creates token" $
       newAccessToken jwk rng uid t1

  _ <- assertRight' "verifies token" $
       verifyAccessToken (JWKSet pubs) t0 tok


  pure ()

