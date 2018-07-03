{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import           OIDC.Server.UserStore.Memory (initUserStore)
import           OIDC.Web (application)
import           OIDC.Web.Monad (Web, initWeb)

import qualified Network.Wai.Handler.Warp as Warp

initEnv :: IO Web
initEnv = do
  us <- initUserStore mempty
  initWeb "static" us

main :: IO ()
main = do
  env <- initEnv
  app <- application env
  Warp.runSettings settings app
  where
    settings =
      Warp.setHost "dev.localhost.com"
      $ Warp.setPort 8080
      Warp.defaultSettings
