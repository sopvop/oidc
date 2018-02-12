module Main where

import           Test.Tasty                (defaultMain, testGroup)

import qualified Tests.OIDC.Crypto.Message

main = defaultMain $ testGroup "OIDC"
   [ Tests.OIDC.Crypto.Message.testTree ]
