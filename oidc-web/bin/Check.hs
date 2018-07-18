{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import           Data.Maybe (fromJust)

import           Data.Time (getCurrentTime)
import           OIDC.Server.UserStore.Memory (initUserStore)
import           OIDC.Web (application)
import           OIDC.Web.Monad
    (Environment (..), Web, initWeb, initWebCrypto, newKey)

import           OIDC.Types (Password (..))
import           OIDC.Types.Email (parseEmailAddress)
import           OIDC.Types.UserAuth
    (EmailStatus (..), UserAuth (..), Username (..), userIdFromString)
import           Servant.Auth.Server (generateKey)


import qualified Network.Wai.Handler.Warp as Warp

initEnv :: IO Web
initEnv = do
  t <- getCurrentTime
  us <- initUserStore
        [
          let
            uid = fromJust $
                  userIdFromString "8c9cc16d-fd63-41bd-91c0-d6f94def0096"
            email = fromJust $ parseEmailAddress "foo@bar.com"

          in UserAuth uid (Username "user1")
             (Password "$pbkdf2_sha256$100000$rAIFsBg2l4pTBcb.5laeau$GhMJ3jtsgprrRys2Q63EwM21.d4JbCbwKpZFNfnyage") -- test1password
             email EmailVerified Nothing "" "user1" Nothing t
        ]
  key <- newKey
  cry <- initWebCrypto key
  jwk <- generateKey
  initWeb TestingEnvironment "static" us cry jwk

main :: IO ()
main = do
  env <- initEnv
  app <- application env
  putStrLn "Running on http://dev.localhost.com:8080"
  Warp.runSettings settings app
  where
    settings =
      Warp.setHost "dev.localhost.com"
      $ Warp.setPort 8080
      Warp.defaultSettings
