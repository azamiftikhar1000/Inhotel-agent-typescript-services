'use strict';

const ApiGateway = require('moleculer-web');

const Auth = require('@libs-private/service-logic/mixins/auth');
import { internalRoute } from './routes/internal';
import { publicRoute } from './routes/public';
const Buildable = require('@libs-private/service-logic/mixins/buildable');

const adminUrls = [
  "http://localhost:4200",
  "https://admin-development.internal.event.dev",
  "https://admin.internal.event.dev"
]

module.exports = {
  name: 'api',
  version: 1,
  mixins: [Auth(), Buildable(), ApiGateway],

  settings: {
    ip: process.env.HOST || '0.0.0.0',
    port: process.env.PORT || 3001,
    optimizeOrder: false,

    use: [],
    rateLimit: {
      // How long to keep record of requests in memory (in milliseconds).
      // Defaults to 60000 (1 min)
      window: 1000,

      // Max number of requests during window. Defaults to 30
      limit: 50,

      // Set rate limit headers to response. Defaults to false
      headers: true,

      // Function used to generate keys. Defaults to:
      key: (req: any) => {
        return (
          req.headers['x-forwarded-for'] ||
          req.connection.remoteAddress ||
          req.socket.remoteAddress ||
          req.connection.socket.remoteAddress
        );
      },
    },
    routes: [
      {
        name: 'health',
        path: '/healthz',
        aliases: {
          'GET /': 'v1.api.health',
        },
        cors: {
          origin: '*',
          methods: ['GET'],
          credentials: false,
        },
        bodyParsers: {
          json: {
            strict: false,
            limit: '5MB',
          },
          urlencoded: {
            extended: true,
            limit: '1MB',
          },
        },
      },
      internalRoute(),
      publicRoute(),
      {
        name: 'auth',
        path: '/auth',
        aliases: {
          'POST /:type': 'v3.users.auth',
        },
        cors: {
          origin: '*',
          methods: ['GET', 'OPTIONS', 'POST', 'PUT', 'DELETE', 'PATCH'],
          credentials: false,
        },
        bodyParsers: {
          json: {
            strict: false,
            limit: '5MB',
          },
          urlencoded: {
            extended: true,
            limit: '1MB',
          },
        },
        async onBeforeCall(ctx: any, route: any, req: any, res: any) {
          const auth = this.auth();
          const token = auth.getToken(req);
          let isValidBuildableCoreToken = auth.verifyCoreToken(token);

          if (isValidBuildableCoreToken) {
            const decodedToken = auth.decodeToken(req);

            ctx.meta.buildable = {
              _id: decodedToken.buildableId,
              buildableId: decodedToken.buildableId,
            };

            ctx.meta.user = {
              _id: decodedToken._id,
              email: decodedToken.email,
            };
          }
          if (adminUrls.some((url) => req.headers.origin?.includes(url))) {
            ctx.meta.isAdmin = true;
          }
        },
      },
    ],

    // Serve assets from "public" folder
    assets: {
      folder: 'public',
    },
  },
  actions: {
    async health(ctx: any) {},
  },
  /**
   * Methods
   */
  methods: {
    authorize(ctx: any, route: any, req: any, res: any) {
      const auth = this.auth();
      const buildable = this.buildable();

      const buildableResponse = buildable.handleBuildableAuthorization(req);

      if (buildableResponse.verified) {
        ctx.meta.buildable = buildableResponse.buildableObject;

        const authorization = auth.handleAuthorization(req, ctx);

        if (authorization.tokenVerified) {
          ctx.meta.user = authorization;
          ctx.meta.req = { url: req.url };
          return Promise.resolve(ctx);
        }

        return Promise.reject(authorization.error);
      }

      return Promise.reject(buildableResponse.error);
    },
  },
};
