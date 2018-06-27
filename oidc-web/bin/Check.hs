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
  putStrLn "huita"
  env <- initEnv

  Warp.runSettings settings (application env)
  where
    settings = Warp.setPort 8080
               Warp.defaultSettings
