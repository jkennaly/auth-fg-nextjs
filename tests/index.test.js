// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';
import Auth from '../index';

import jwt from 'jsonwebtoken';
import { beforeEach } from 'vitest';
import { debug } from 'console';

const basicToken = {
    foo: "bar"
}

describe('Auth Handler class for festigram nextjs', async () => {
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


})