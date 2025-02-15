{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}
module Yesod.Auth.OAuth2.Dispatch
    ( FetchCreds
    , dispatchAuthRequest
    ) where

import Control.Exception.Safe
import Control.Monad (unless, (<=<))
import Data.Monoid ((<>))
import Data.Text (Text)
import qualified Data.Text as T
import Data.Text.Encoding (encodeUtf8)
import Network.HTTP.Conduit (Manager)
import Network.OAuth.OAuth2
-- import Network.OAuth.OAuth2.Internal (OAuth2Token)
import System.Random (newStdGen, randomRs)
import URI.ByteString.Extension
import URI.ByteString (URIRef (uriAuthority), Authority (authorityHost), Host (hostBS))
import Yesod.Auth hiding (ServerError)
import Yesod.Auth.OAuth2.ErrorResponse
import Yesod.Auth.OAuth2.Exception
import qualified Yesod.Auth.OAuth2.StripeConnect.StripeToken as StripeToken
import Yesod.Core hiding (ErrorResponse)

-- | How to take an @'OAuth2Token'@ and retrieve user credentials
type FetchCreds m = Manager -> OAuth2Token -> IO (Creds m)

-- | Dispatch the various OAuth2 handshake routes
dispatchAuthRequest
    :: Text             -- ^ Name
    -> OAuth2           -- ^ Service details
    -> FetchCreds m     -- ^ How to get credentials
    -> Text             -- ^ Method
    -> [Text]           -- ^ Path pieces
    -> AuthHandler m TypedContent
dispatchAuthRequest name oauth2 _ "GET" ["forward"] =
    dispatchForward name oauth2
dispatchAuthRequest name oauth2 getCreds "GET" ["callback"] =
    dispatchCallback name oauth2 getCreds
dispatchAuthRequest _ _ _ _ _ = notFound

-- | Handle @GET \/forward@
--
-- 1. Set a random CSRF token in our session
-- 2. Redirect to the Provider's authorization URL
--
dispatchForward :: Text -> OAuth2 -> AuthHandler m TypedContent
dispatchForward name oauth2 = do
    csrf <- setSessionCSRF $ tokenSessionKey name
    oauth2' <- withCallbackAndState name oauth2 csrf
    redirect $ toText $ authorizationUrl oauth2'

-- | Handle @GET \/callback@
--
-- 1. Verify the URL's CSRF token matches our session
-- 2. Use the code parameter to fetch an AccessToken for the Provider
-- 3. Use the AccessToken to construct a @'Creds'@ value for the Provider
--
dispatchCallback :: Text -> OAuth2 -> FetchCreds m -> AuthHandler m TypedContent
dispatchCallback name oauth2 getCreds = do
    csrf <- verifySessionCSRF $ tokenSessionKey name
    onErrorResponse errInvalidOAuth
    code <- requireGetParam "code"
    manager <- authHttpManager
    creds <- fetchCreds oauth2 csrf code manager
    setCredsRedirect creds

  where
    errLeft :: Show e => IO (Either e a) -> AuthHandler m a
    errLeft = either (errInvalidOAuth . unknownError . tshow) pure <=< liftIO

    errInvalidOAuth :: ErrorResponse -> AuthHandler m a
    errInvalidOAuth err = do
        $(logError) $ "OAuth2 error (" <> name <> "): " <> tshow err
        redirectMessage $ "Unable to log in with OAuth2: " <> erUserMessage err

    fetchCreds oa csrf code manager = do
      let mHost = (hostBS . authorityHost) <$> (uriAuthority . oauthAccessTokenEndpoint) oa

      if mHost == (Just "connect.stripe.com")
        then fetchStripeConnectCreds oa csrf code manager
        else fetchCreds' oa csrf code manager

    fetchCreds' oa csrf code manager = do
      oa' <- withCallbackAndState name oa csrf
      token <- errLeft $ fetchAccessToken manager oa' $ ExchangeToken code
      errLeft $ tryFetchCreds $ getCreds manager token

    fetchStripeConnectCreds oa csrf code manager = do
      stripe <- errLeft $ liftIO $ StripeToken.fetch oa csrf code manager
      let token = OAuth2Token (AccessToken $ StripeToken.accessToken stripe) (Just $ RefreshToken $ StripeToken.refreshToken stripe) Nothing (Just $ StripeToken.tokenType stripe) Nothing
      errLeft $ tryFetchCreds $ getCreds manager token
      -- pure $ Creds "stripe_connect" (StripeToken.stripeUserId stripe) (StripeToken.stripeExtra stripe)

redirectMessage :: Text -> AuthHandler m a
redirectMessage msg = do
    toParent <- getRouteToParent
    setMessage $ toHtml msg
    redirect $ toParent LoginR

tryFetchCreds :: IO a -> IO (Either SomeException a)
tryFetchCreds f =
    (Right <$> f)
        `catch` (\(ex :: IOException) -> pure $ Left $ toException ex)
        `catch` (\(ex :: YesodOAuth2Exception) -> pure $ Left $ toException ex)

withCallbackAndState :: Text -> OAuth2 -> Text -> AuthHandler m OAuth2
withCallbackAndState name oauth2 csrf = do
    let url = PluginR name ["callback"]
    render <- getParentUrlRender
    let callbackText = render url

    callback <-
        maybe
                (liftIO
                $ throwString
                $ "Invalid callback URI: "
                <> T.unpack callbackText
                <> ". Not using an absolute Approot?"
                )
                pure
            $ fromText callbackText

    pure oauth2
        { oauthCallback = Just callback
        , oauthOAuthorizeEndpoint =
            oauthOAuthorizeEndpoint oauth2
                `withQuery` [("state", encodeUtf8 csrf)]
        }

getParentUrlRender :: MonadHandler m => m (Route (SubHandlerSite m) -> Text)
getParentUrlRender = (.) <$> getUrlRender <*> getRouteToParent

-- | Set a random, 30-character value in the session
setSessionCSRF :: MonadHandler m => Text -> m Text
setSessionCSRF sessionKey = do
    csrfToken <- liftIO randomToken
    csrfToken <$ setSession sessionKey csrfToken
    where randomToken = T.pack . take 30 . randomRs ('a', 'z') <$> newStdGen

-- | Verify the callback provided the same CSRF token as in our session
verifySessionCSRF :: MonadHandler m => Text -> m Text
verifySessionCSRF sessionKey = do
    token <- requireGetParam "state"
    sessionToken <- lookupSession sessionKey
    deleteSession sessionKey

    unless (sessionToken == Just token)
        $ permissionDenied "Invalid OAuth2 state token"

    return token

requireGetParam :: MonadHandler m => Text -> m Text
requireGetParam key = do
    m <- lookupGetParam key
    maybe errInvalidArgs return m
  where
    errInvalidArgs = invalidArgs ["The '" <> key <> "' parameter is required"]

tokenSessionKey :: Text -> Text
tokenSessionKey name = "_yesod_oauth2_" <> name

tshow :: Show a => a -> Text
tshow = T.pack . show
