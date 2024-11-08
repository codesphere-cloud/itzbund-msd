import { getKcContext } from "keycloakify/lib/getKcContext";

export const { kcContext } = getKcContext({
    /* Uncomment to test the login page with mock data */
    "mockPageId": "login-update-password.ftl",
    "mockData": [
        {
            "pageId": "login-reset-password.ftl",
            "locale": {
                "currentLanguageTag": "de", //When we test the login page we do it in french
            },
        },
    ],
});

export type KcContext = NonNullable<typeof kcContext>;
