package org.example;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.AnonymousAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.*;


public class Main {

    private static final String COGNITO_USER_POOL_ID = "eu-central-1_P8l0OEy9K";
    private static final String OAUTH2_CLIENT_ID = "4glpu5pe80ae05b2bfs24p9m7n";
    private static final String USERNAME = "sebastien.blanchard@careside.care";
    private static final String PASSWORD = "xlpRIVuBDvwY6!Fv";

    private static AuthenticationHelper authenticationHelper = new AuthenticationHelper(COGNITO_USER_POOL_ID,OAUTH2_CLIENT_ID,COGNITO_USER_POOL_ID);

    public static void main(String[] args) {

        String tokenJWT = PerformSRPAuthentication(USERNAME,PASSWORD);
        System.out.println("Your token: " + tokenJWT);

    }

    static String PerformSRPAuthentication(String username, String password) {
        String authresult = null;

        InitiateAuthRequest initiateAuthRequest = authenticationHelper.initiateUserSrpAuthRequest(username);

        try {
            AnonymousAWSCredentials awsCreds = new AnonymousAWSCredentials();

            AWSCognitoIdentityProvider cognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder
                    .standard()
                    .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
                    .withRegion(Regions.EU_CENTRAL_1)
                    .build();

            InitiateAuthResult initiateAuthResult = cognitoIdentityProvider.initiateAuth(initiateAuthRequest);

            if (ChallengeNameType.PASSWORD_VERIFIER.toString().equals(initiateAuthResult.getChallengeName())) {
                RespondToAuthChallengeRequest challengeRequest = authenticationHelper.userSrpAuthRequest(initiateAuthResult, password,initiateAuthRequest.getAuthParameters().get("SECRET_HASH"));
                RespondToAuthChallengeResult result = cognitoIdentityProvider.respondToAuthChallenge(challengeRequest);
                authresult = result.getAuthenticationResult().getIdToken();
            }

        } catch (final Exception ex) {
            System.out.println("Exception" + ex);

        }
        return authresult;
    }




}

