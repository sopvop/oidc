module Main where

import           Test.Tasty (defaultMain, testGroup)

import qualified Tests.OIDC.Crypto.Jwt
import qualified Tests.OIDC.Crypto.Message
import qualified Tests.OIDC.Server.KeyStore.Memory
import qualified Tests.OIDC.Server.UserStore.Memory

main :: IO ()
main = defaultMain $ testGroup "OIDC"
   [ Tests.OIDC.Crypto.Jwt.testTree
   , Tests.OIDC.Crypto.Message.testTree
   , Tests.OIDC.Server.KeyStore.Memory.testTree
   , Tests.OIDC.Server.UserStore.Memory.testTree
   ]
