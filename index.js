import isArray from "lodash/isArray"
import isInteger from "lodash/isInteger"
import jwt_decode from "jwt-decode"
const headerBase = {
    "Content-Type": "application/json"
}

var dataReset = () => true

const tokenIsValid = token => {
    if (!token) return false
    const decoded = jwt_decode(token)
    const expiration = decoded.exp * 1000
    const now = Date.now()
    const expired = expiration - now < 0
    //console.log(expiration, now, expired)
    return !expired
}

const clean = () => {
    localStorage.clear()
    dataReset()
}

const authLoad = window.mockery
    ? Promise.reject("mocked")
    : Promise.resolve(true)

const userIdFromToken = apiUrl => async (authResult) => {
    const localId = JSON.parse(localStorage.getItem("ft_user_id"))
    if (localId) return localId
    try {
        const timeout = 1000
        const controller = new AbortController()
        const timer = setTimeout(() => {
            //console.log('fetchT timed out')
            return controller.abort()
        }, timeout)
        const response = await fetch(apiUrl + "/api/Profiles/getUserId/", {
            method: "post",
            cache: "no-store",
            credentials: "include",
            signal: controller.signal,
            headers: new Headers(
                authResult
                    ? Object.assign({}, headerBase, {
                        Authorization: `Bearer ${authResult}`,

                    })
                    : headerBase
            ),
        })
        clearTimeout(timer)
        const { id } = await response.json()
        if (!id) throw "invalid id received from getFtUserId() " + id
        if (isInteger(id)) localStorage.setItem("ft_user_id", id)
        return id
    } catch (err) {
        console.error(err)
    }
}

export default class Auth {
    constructor(AUTH_DATA, API_URL) {
        this.AUTH_DATA = AUTH_DATA
        this.apiUrl = API_URL
    }
    login(prev) {
        authLoad
            .then(() => {
                lastState = {
                    route: prev,
                }
                window.location.assign(
                    this.AUTH_DATA.LOGINURL +
                    `?cb=${encodeURIComponent(this.AUTH_DATA.CALLBACKURL)}`
                )
            })
            .catch(err => console.error("login error", err))
    }

    handleAuthentication() {
        const query = window.location.href
        //console.log('local handleAuthentication', query)

        const token = query.match(/[?&]token=([^&]+).*$/)[1]
        //console.log('handleAuthentication query', query, token)

        //store the token
        localStorage.setItem("local_token", token)
        //console.log('local_token reload', localStorage.getItem('local_token'))
        //get the ftUserId
        return this.getFtUserId()
            .then(id => localStorage.setItem("ft_user_id", id))
            .then(() => this.getRoles())
            .then(roles =>
                localStorage.setItem("ft_user_roles", JSON.stringify(roles))
            )
    }

    gtt() {
        //console.log('auth gtt')
        //console.log(gttCache)
        const local = localStorage.getItem("gtt")
        return local
    }

    userGtt() {
        //console.log('auth gtt')
        //console.log(gttCache)
        const local = this.gtt()
        if (local) return jwt_decode(local)
        return {}
    }

    userId() {
        //console.log('auth userId')
        //console.log(userIdCache)
        const local = parseInt(localStorage.getItem("ft_user_id"), 10)
        if (local) return local
        if (local === NaN) localStorage.clearItem("ft_user_id")
        return 0
    }

    userRoles() {
        //console.log('auth userId')
        //console.log(userIdCache)
        try {
            const local = JSON.parse(localStorage.getItem("ft_user_roles"))
            if (local) return local
        } catch (err) {
            return []
        }
    }

    //returns a promise that resolves to a userIdCache
    getFtUserId() {
        return this.getAccessToken().then(userIdFromToken(this.apiUrl))
    }

    logout(skipRoute) {
        // Clear Access Token and ID Token from local storage
        clean()
        window.location.assign("/")
    }

    isAuthenticated() {
        return this.getIdTokenClaims().then(
            claims => claims && claims.exp > Date.now() / 1000
        )
    }

    async getAccessToken() {
        //console.log('trying to retrieve token')
        const localToken = localStorage.getItem("local_token")
        const localValid = tokenIsValid(localToken)
        if (localValid) return localToken
        //try for refresh
        if (localToken && !this.refreshing) {
            this.refreshing = true
            try {
                const timeout = 1000
                const controller = new AbortController()
                const timer = setTimeout(() => {
                    //console.log('fetchT timed out')
                    return controller.abort()
                }, timeout)
                const response = await fetch(this.apiUrl + "/authorize/refresh", {
                    method: "get",
                    cache: "no-store",
                    credentials: "include",
                    signal: controller.signal,
                    headers: new Headers(
                        authResult
                            ? Object.assign({}, headerBase, {
                                Authorization: `Bearer ${authResult}`,

                            })
                            : headerBase
                    ),
                })
                clearTimeout(timer)
                const { token } = await response.json()
                if (token) {
                    localStorage.setItem("local_token", token)
                    return token
                }
            } catch (err) {
                if (err && err.code) {
                    clean()
                } else {
                    return ''
                }

            } finally {
                this.refreshing = false
            }
        }
        throw new Error('login required')
    }

    async getGttRawRemote() {
        if (this.gettinGtt) return Promise.resolve('')
        this.gettinGtt = true
        return (
            this.getAccessToken()
                .then(authResult => {
                    if (typeof authResult !== 'string') throw new Error("not authorized")
                    return authResult
                })
                .then(authResult => {
                    const timeout = 1000
                    const controller = new AbortController()
                    const id = setTimeout(() => {
                        //console.log('fetchT timed out')
                        return controller.abort()
                    }, timeout)
                    const response = await fetch(this.apiUrl + "/api/Profiles/gtt", {
                        method: "get",
                        cache: "no-store",
                        credentials: "include",
                        signal: controller.signal,
                        headers: new Headers(
                            authResult
                                ? Object.assign({}, headerBase, {
                                    Authorization: `Bearer ${authResult}`,

                                })
                                : headerBase
                        ),
                    })
                    clearTimeout(id)
                    return response
                })
                .then(response => {
                    //console.log('gtt', response)
                    if (isArray(response)) return response
                    try {
                        return response.json()
                    } catch (err) {
                        console.error(err)
                        return []
                    }
                })
                .then(json => json.token)
                .then(gtt => {
                    localStorage.setItem("gtt", gtt)
                    this.gettinGtt = false
                    return gtt
                })
                .catch(err => {
                    if (err.error === 'login_required' || err === 'login required' || err.message === 'login required' || err === 'auth fail') return
                    console.error(err)
                })
        )
    }

    async getGttRaw() {
        const local = this.gtt()
        return local ?? this.getGttRawRemote()
    }

    async getGttDecoded() {

        return this.getGttRaw().then(jwt_decode)
    }

    getBothTokens() {
        const access = this.getAccessToken()
        const gtt = this.getGttRaw()
        return Promise.all([access, gtt])
    }
    getIdTokenClaims() {
        return this.getAccessToken().then(jwt_decode)
    }
    getRoles() {
        return this.getIdTokenClaims().then(
            claims => claims["https://festigra1app/roles"]
        )
    }
    cacheCleaner(dataClear) {
        dataReset = dataClear
    }
}