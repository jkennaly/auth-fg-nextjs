import Core from '@0441design/auth-fg-browser'
import jwt from 'express-jwt'
import jwks from 'jwks-rsa'

let userPromise;

let authConfig = {}

export default function setup({ authData, apiUrl }) {
    authConfig = new Core(authData, apiUrl);
}


export const withApiAuthRequired = async (apiPage) => (req, res) => {
    try {
        jwt({
            secret: jwks.expressJwtSecret({
                cache: true,
                rateLimit: true,
                jwksRequestsPerMinute: 5,
                jwksUri: "https://api.festigram.app/keys"
            }),
            audience: 'https://festigram.app/api/',
            issuer: 'https://festigram.app/',
            algorithms: ['RS256']
        })
        return apiPage(req, res);
    } catch (e) {
        console.log(e);
        return res.status(401).json({
            error: 'Unauthorized'
        });
    }
}

export const withPageAuthRequired = async (page) => {
    if (!authConfig.getRoles) throw new Error("authConfig.getRoles is not defined");
    try {

        const roles = await authConfig.getRoles()
        if (!roles || !roles.length) throw new Error('No roles found')
        return page
    } catch (error) {
        console.log(error)
        //redirect to login
    }


}

export const getAccessToken = async (...args) => {
    if (!authConfig.getAccessToken) throw new Error("authConfig.getAccessToken is not defined");
    return authConfig.getAccessToken(args)
}

export const useUser = () => {
    if (!authConfig.getIdTokenClaims) throw new Error("authConfig.getIdTokenClaims is not defined");
    if (!userPromise) {
        userPromise = makeQuerablePromise(authConfig.getIdTokenClaims())
        return {
            isLoading: true
        }
    }
    if (userPromise.isFulfilled()) {
        return {
            isLoading: false,
            user: userPromise.value(),
        }
    }
    if (userPromise.isPending()) {
        return {
            isLoading: true
        }
    }
    if (userPromise.isRejected()) {
        return {
            isLoading: false,
            error: userPromise.reason()
        }
    }
    return {
        error: 'Unknown error'
    }
}


/**
 * From: https://ourcodeworld.com/articles/read/317/how-to-check-if-a-javascript-promise-has-been-fulfilled-rejected-or-resolved
 * This function allow you to modify a JS Promise by adding some status properties.
 * Based on: http://stackoverflow.com/questions/21485545/is-there-a-way-to-tell-if-an-es6-promise-is-fulfilled-rejected-resolved
 * But modified according to the specs of promises : https://promisesaplus.com/
 */
function makeQuerablePromise(promise) {
    // Don't modify any promise that has been already modified.
    if (promise.isFulfilled) return promise;

    // Set initial state
    var isPending = true;
    var isRejected = false;
    var isFulfilled = false;
    var value, reason;

    // Observe the promise, saving the fulfillment in a closure scope.
    var result = promise.then(
        function (v) {
            isFulfilled = true;
            isPending = false;
            value = v;
            return v;
        },
        function (e) {
            isRejected = true;
            isPending = false;
            reason = e;
            throw e;
        }
    );

    result.isFulfilled = function () { return isFulfilled; };
    result.isPending = function () { return isPending; };
    result.isRejected = function () { return isRejected; };
    result.value = function () { return value; };
    result.reason = function () { return reason; };
    return result;
}