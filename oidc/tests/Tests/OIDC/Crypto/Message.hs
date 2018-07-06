{-# LANGUAGE OverloadedStrings #-}
module Tests.OIDC.Crypto.Message
  ( testTree
  ) where

import           Control.Monad.IO.Class (liftIO)

import           Test.QuickCheck.Monadic
import           Test.Tasty
import           Test.Tasty.QuickCheck

import           OIDC.Crypto.Message
import           OIDC.Crypto.RNG


testTree :: TestTree
testTree = testGroup "Tests.OIDC.Crypto.Message"
    [ testMessageRoundTrip
    ]


testMessageRoundTrip :: TestTree
testMessageRoundTrip = testProperty "encryptMessage roundtrip" prop
  where
    prop bs = monadicIO $ do
      e <- liftIO $ do
        rng <- newRNG
        encryptMessage key rng (bs :: Int)
      pure $ decryptMessage key e == Just bs

    key = SymKey "0123456789abcdef0123456789abcdef"
