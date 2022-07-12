import jwt_decode from "jwt-decode"
const headerBase = {
    "Content-Type": "application/json"
}

var dataReset = () => true
let lastState = {}

const tokenIsValid = token => {
    if (!token) return false
    try {
        const decoded = jwt_decode(token)
        const expiration = decoded.exp * 1000
        const now = Date.now()
        const expired = expiration - now < 0
        return !expired
    } catch (err) {
        return false
    }
}

const clean = () => {
    localStorage.clear()
    return dataReset()
}

const userIdFromToken = apiUrl => async (authResult) => {
    const localId = JSON.parse(localStorage.getItem("ft_user_id"))
    if (localId) return localId
    try {
        const timeout = 1000
        const controller = new AbortController()
        const timer = setTimeout(() => {
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
        const json = await response.json()
        const id = json.id
        if (!id) throw "invalid id received from getFtUserId() " + id
        if (typeof id === 'number') localStorage.setItem("ft_user_id", id)
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
        lastState = {
            route: prev,
        }
        clean()
        const url = `${this.AUTH_DATA.LOGINURL}?cb=${encodeURIComponent(this.AUTH_DATA.CALLBACKURL)}`
        window.location.assign(url)
        return url
    }

    gtt() {
        const local = localStorage.getItem("gtt")
        return local
    }

    userGtt() {
        const local = this.gtt()
        try {
            if (local) return jwt_decode(local)
        } catch (err) {
            return {}
        }
    }

    userId() {
        const local = parseInt(localStorage.getItem("ft_user_id"), 10)
        if (local) return local
        if (local === NaN) localStorage.clearItem("ft_user_id")
        return 0
    }

    userRoles() {
        try {
            const local = JSON.parse(localStorage.getItem("ft_user_roles"))
            if (local) return local
            return []
        } catch (err) {
            return []
        }
    }

    logout(skipRoute) {
        // Clear Access Token and ID Token from local storage
        clean()
        window.location.assign("/")
    }
    cacheCleaner(dataClear) {
        dataReset = dataClear
    }

    async getAccessToken() {
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
                    return controller.abort()
                }, timeout)
                const response = await fetch(this.apiUrl + "/authorize/refresh", {
                    method: "get",
                    cache: "no-store",
                    credentials: "include",
                    signal: controller.signal,
                    headers: new Headers(
                        localToken
                            ? Object.assign({}, headerBase, {
                                Authorization: `Bearer ${localToken}`,

                            })
                            : headerBase
                    ),
                })
                clearTimeout(timer)
                if (!response.ok) throw response
                const { token } = await response.json()
                if (token) {
                    localStorage.setItem("local_token", token)
                    return token
                } else throw response
            } catch (err) {
                if (err && err.status === 403) {
                    clean()
                    return ''
                } else {
                    return ''
                }

            } finally {
                this.refreshing = false
            }
        }
        throw new Error('login required')
    }

    getFtUserId() {
        return this.getAccessToken().then(userIdFromToken(this.apiUrl))
    }
    async getIdTokenClaims() {
        try {
            const token = await this.getAccessToken()
            const decoded = jwt_decode(token)
            return decoded
        } catch (err) {
            return {}
        }
    }

    isAuthenticated() {
        return this.getIdTokenClaims().then(
            claims => claims && claims.exp > Date.now() / 1000
        )
    }
    async getRoles() {
        const claims = await this.getIdTokenClaims()
        return claims["https://festigram.app/roles"]
    }

    handleAuthentication() {
        const query = window.location.href

        const token = query.match(/[?&]token=([^&]+).*$/)[1]

        //store the token
        localStorage.setItem("local_token", token)
        //get the ftUserId
        return this.getFtUserId()
            .then(id => localStorage.setItem("ft_user_id", id))
            .then(() => this.getRoles())
            .then(roles => {
                localStorage.setItem("ft_user_roles", JSON.stringify(roles))
            })
    }

    async getGttRawRemote() {
        if (this.gettinGtt) return Promise.resolve('')
        this.gettinGtt = true
        try {
            const authResult = await this.getAccessToken()
            if (typeof authResult !== 'string') throw new Error("not authorized")
            const timeout = 1000
            const controller = new AbortController()
            const id = setTimeout(() => {
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
            if (!response.ok) throw response
            const { token: gtt } = await response.json()
            localStorage.setItem("gtt", gtt)
            this.gettinGtt = false
            return gtt
        } catch (err) {
            if (err.error === 'login_required' || err === 'login required' || err.message === 'login required' || err === 'auth fail') return ''
            this.gettinGtt = false
            return ''
        }
    }

    async getGttRaw() {
        const local = this.gtt()
        return local ?? this.getGttRawRemote()
    }

    async getGttDecoded() {
        try {
            return this.getGttRaw().then(jwt_decode)
        } catch (err) {
            return {}
        }
    }
}
