// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import Auth from '../index';

import jwt from 'jsonwebtoken';
import { beforeEach } from 'vitest';
import { debug } from 'console';

const basicToken = {
    foo: "bar"
}

describe('Auth Handler class for festigram sites', async () => {
    /*
    const { location } = window;
    beforeAll(() => {
        delete window.location;
        window.location = { reload: vi.fn() };
    });

    afterAll(() => {
        window.location = location;
    });
    */

    beforeEach(() => {
        window.location.assign("http://dummy.com");
        localStorage.clear()
    });
    it('mocks `assign`', () => {
        expect(vi.isMockFunction(window.location.assign)).toBe(true);
    });

    it('calls `assign`', () => {
        window.location.assign('abc');
        expect(window.location.assign).toHaveBeenCalled();
    });
    it('calls `assign again`', () => {
        window.location.assign('abc');
        expect(window.location.assign).toHaveBeenCalled();
    });
    it('should redirect to login page', async () => {
        const data = { LOGINURL: 'http://localhost:3000/login', CALLBACKURL: 'http://dummy.com/callback' }
        const auth = new Auth(data, 'http://localhost:3000/api');
        const prev = '/'
        auth.login(prev)
        const finalUrl = `${data.LOGINURL}?cb=${encodeURIComponent(data.CALLBACKURL)}`
        expect(window.location.assign).toHaveBeenCalled()
        expect(window.location.assign).toHaveBeenCalledWith(finalUrl)
    })
    it('should return the localStorage gtt', async () => {
        const auth = new Auth({}, '')
        localStorage.setItem('gtt', '123')
        const gtt = auth.gtt()
        expect(gtt).toBe('123')
    })
    it('should return decoded gtt', async () => {
        const auth = new Auth({}, '')
        const token = jwt.sign(basicToken, 'secret', { algorithm: 'none' })
        localStorage.setItem('gtt', token)
        const gtt = auth.userGtt()
        delete gtt.iat
        expect(gtt).toEqual(basicToken)
    })
    it('should return the localStorage ftUserId', async () => {
        const auth = new Auth({}, '')
        const storeId = 123
        localStorage.setItem('ft_user_id', storeId)
        const id = auth.userId()
        expect(id).toBe(storeId)
    })
    it('should return 0', async () => {
        const auth = new Auth({}, '')
        const storeId = 'test'
        localStorage.setItem('ft_user_id', storeId)
        const id = auth.userId()
        expect(id).toBe(0)
    })
    it('should return 0', async () => {
        const auth = new Auth({}, '')
        const storeId = undefined
        localStorage.setItem('ft_user_id', storeId)
        const id = auth.userId()
        expect(id).toBe(0)
    })
    it('should return no roles', async () => {
        const auth = new Auth({}, '')
        const roles = await auth.userRoles()
        expect(roles).toEqual([])
    })
    it('should return stored roles', async () => {
        const auth = new Auth({}, '')
        const assignedRoles = ['admin', 'user']
        localStorage.setItem('ft_user_roles', JSON.stringify(assignedRoles))
        const roles = await auth.userRoles()
        expect(roles).toEqual(assignedRoles)
    })
    it('should redirect to clear localStorage and indexeddb', async () => {
        const auth = new Auth({}, '')
        localStorage.setItem('testITem', '123')
        auth.logout()
        expect(localStorage.length).toBe(0)

    })
    it('should redirect to /', async () => {
        const auth = new Auth({}, '')
        auth.logout()
        expect(window.location.assign).toHaveBeenCalled()
        expect(window.location.assign).toHaveBeenCalledWith('/')
    })
    it('should call the callback', async () => {
        const auth = new Auth({}, '')
        localStorage.setItem('test', '1234')
        const callback = () => localStorage.setItem('testITem', '123')
        auth.cacheCleaner(callback)
        auth.logout()
        expect(window.location.assign).toHaveBeenCalled()
        expect(window.location.assign).toHaveBeenCalledWith('/')
        expect(localStorage.length).toBe(1)
        expect(localStorage.getItem('testITem')).toBe('123')
    })
    it('should return the token from localstorage if present & valid', async () => {
        const auth = new Auth({}, '')
        const storedToken = jwt.sign(basicToken, 'secret', { algorithm: 'none' })
        localStorage.setItem('local_token', storedToken)
        const token = await auth.getAccessToken()
        expect(token).toBe(storedToken)
    })
    it('should not call refresh if token is missing', async () => {
        const tokenValue = jwt.sign(basicToken, 'secret', { algorithm: 'none' })
        fetch.mockResponse(JSON.stringify({ token: tokenValue }));
        const auth = new Auth({}, '')
        try {
            const token = await auth.getAccessToken()
        } catch (e) {
            expect(e.message).toBe('login required')
        }
        expect(localStorage.getItem('local_token')).toBe(null)
    })
    it('should timeout if refresh response is slow', async () => {
        const tokenResponse = jwt.sign(basicToken, 'secret', { algorithm: 'none' })
        const tokenValue = '12345'
        localStorage.setItem('local_token', tokenValue)
        fetch.mockResponse(async () => {
            await sleep(1000)
            return JSON.stringify({ token: tokenResponse })
        });
        const auth = new Auth({}, '')
        const token = await auth.getAccessToken()
        expect(token).toBe('')
        expect(fetch.mock.calls.length).toBe(1)
    })
    it('should clean localstorage if refresh rejected', async () => {
        const tokenResponse = jwt.sign(basicToken, 'secret', { algorithm: 'none' })
        const tokenValue = '12345'
        localStorage.setItem('test_key', tokenValue)
        localStorage.setItem('local_token', tokenValue)
        fetch.mockResponse(async () => ({ status: 401 }));
        const auth = new Auth({}, '')
        const token = await auth.getAccessToken()
        expect(token).toBe('')
        expect(fetch.mock.calls.length).toBe(1)

    })
    it('should return the remote ftUserId', async () => {
        const tokenResponse = jwt.sign(basicToken, 'secret', { algorithm: 'none' })
        const auth = new Auth({}, '')
        localStorage.setItem('local_token', tokenResponse)
        const tokenValue = 12345
        fetch.mockResponse(JSON.stringify({ id: tokenValue }));
        const id = await auth.getFtUserId()
        expect(id).toBe(tokenValue)
        expect(parseInt(localStorage.getItem('ft_user_id'), 10)).toBe(tokenValue)
    })
    it('should store the token', async () => {
        const auth = new Auth({}, '')
        const roles = ["user"]
        const claimObj = { sub: '123', jti: '123', "https://festigram.app/roles": roles }
        const token = jwt.sign(claimObj, 'secret', { algorithm: 'none' })
        const baseUrl = 'http://localhost:3000/'
        window.location.href = (baseUrl + '?token=' + token)
        expect(window.location.href).toBe(baseUrl + '?token=' + token)
        const tokenValue = 12345
        fetch.mockResponse(JSON.stringify({ id: tokenValue }));
        await auth.handleAuthentication()
        expect(localStorage.getItem('local_token')).toBe(token)
        expect(localStorage.getItem('ft_user_roles')).toEqual(JSON.stringify(roles))
        expect(parseInt(localStorage.getItem('ft_user_id'), 10)).toBe(tokenValue)
    })
    it('should get token access claims', async () => {
        const auth = new Auth({}, '')
        const storedToken = jwt.sign(basicToken, 'secret', { algorithm: 'none' })
        localStorage.setItem('local_token', storedToken)
        const claims = await auth.getIdTokenClaims(true)
        delete claims.iat
        expect(claims).toEqual(basicToken)
    })
    it('should verify authentication', async () => {
        const auth = new Auth({}, '')
        const claimObj = { sub: '123', jti: '123' }
        const token = jwt.sign(claimObj, 'secret', { algorithm: 'none', expiresIn: '1d' })
        localStorage.setItem('local_token', token)
        const verified = await auth.isAuthenticated()
        expect(verified).toBe(true)
    })
    it('should get remote gtt', async () => {

        expect(fetch.mock.calls.length).toBe(0)
        const claimObj = { sub: '123', jti: '123' }
        const accessToken = jwt.sign(claimObj, 'secret', { algorithm: 'none', expiresIn: '1d' })
        localStorage.setItem('local_token', accessToken)
        const tokenValue = '12345'
        fetch.mockResponse(JSON.stringify({ token: tokenValue }));
        const auth = new Auth({}, '')
        const token = await auth.getGttRawRemote()
        expect(token).toBe(tokenValue)
        const token2 = await auth.getGttRawRemote()
        expect(token2).toBe(tokenValue)
        expect(fetch.mock.calls.length).toBe(2)
        expect(localStorage.getItem('gtt')).toBe(tokenValue)
    })
    it('should timeout if gtt response is slow', async () => {
        expect(fetch.mock.calls.length).toBe(0)
        expect(localStorage.getItem('gtt')).toBe(null)
        const storedToken = jwt.sign(basicToken, 'secret', { algorithm: 'none' })
        localStorage.setItem('local_token', storedToken)
        const tokenValue = '12345'
        fetch.mockResponse(async () => {
            await sleep(1000)
            return JSON.stringify({ token: tokenValue })
        });
        const auth = new Auth({}, '')
        const token = await auth.getGttRawRemote()
        expect(token).toBe('')
        expect(fetch.mock.calls.length).toBe(1)
        expect(localStorage.getItem('gtt')).toBe(null)
    })
    it('should return the gtt from localstorage if present', async () => {
        const auth = new Auth({}, '')
        localStorage.setItem('gtt', '123')
        const token = await auth.getGttRaw()
        expect(token).toBe('123')
    })
    it('should get decoded gtt claims', async () => {
        const auth = new Auth({}, '')
        const claimObj = { sub: '123', jti: '123' }
        const token = jwt.sign(claimObj, 'secret', { algorithm: 'none' })
        localStorage.setItem('gtt', token)
        const claims = await auth.getGttDecoded()
        delete claims.iat
        expect(claims).toEqual(claimObj)
    })
    it('should get access roles', async () => {
        const auth = new Auth({}, '')
        const claimObj = { sub: '123', jti: '123', "https://festigram.app/roles": ["user"] }
        const token = jwt.sign(claimObj, 'secret', { algorithm: 'none' })
        localStorage.setItem('local_token', token)
        const roles = await auth.getRoles()
        expect(roles).toEqual(["user"])
    })

})