import { Context, ServiceBroker } from 'moleculer';
import { ServiceContextMeta } from '@libs-private/data-models/types/genericService';
const MongoDBAdapter = require('moleculer-db-adapter-mongo');
import {
  GenericServiceProvider,
  makeOwnershipFromContextMeta,
} from '@libs-private/service-logic/services/genericService';
import { createLinkSchema } from './schema/create.schema';
import {
  CreateEmbedConnectionPayload,
  CreateEventLinkPayload,
  CreateOauthEmbedConnectionPayload,
} from '@event-inc/types/links';
import { useEventLinksService } from '@libs-private/service-logic/services/event-links/useEventLinksService';
import { createEmbedConnectionSchema } from './schema/createEmbedConnection.schema';
import { createOauthEmbedConnectionSchema } from './schema/createOauthEmbedConnection.schema';

export default class EventLinks extends GenericServiceProvider {
  public constructor(public broker: ServiceBroker) {
    super(broker, {
      name: 'event-links',
      adapter: new MongoDBAdapter(process.env.MONGO_URI),
      version: 1,
      hooks: {},
      collection: 'sessions',
      publicActions: {
        create: [createLinkSchema, publicCreate],

        createEmbedConnection: [
          createEmbedConnectionSchema,
          publicCreateEmbedConnection,
        ],
        createOauthEmbedConnection: [
          createOauthEmbedConnectionSchema,
          publicCreateOauthEmbedConnection,
        ],
        createEmbedToken: [{}, publicCreateEmbedToken],
        createUserDashboardEmbedLinkToken: [
          {},
          createUserDashboardEmbedLinkToken,
        ],
      },
    });
    this.broker.logger.info('[event‑links] service loaded');
  }
}

const publicCreate = async (ctx: Context<unknown, ServiceContextMeta>) => {
  const { create } = useEventLinksService(
    ctx,
    makeOwnershipFromContextMeta(ctx)
  );
  return (await create(ctx.params as CreateEventLinkPayload)).unwrap();
};

const publicCreateEmbedConnection = async (
  ctx: Context<unknown, ServiceContextMeta>
) => {
  const { createEmbedConnection } = useEventLinksService(
    ctx,
    makeOwnershipFromContextMeta(ctx)
  );
  return (
    await createEmbedConnection(ctx.params as CreateEmbedConnectionPayload)
  ).unwrap();
};

const publicCreateOauthEmbedConnection = async (
  ctx: Context<unknown, ServiceContextMeta>
) => {
  const { createOauthEmbedConnection } = useEventLinksService(
    ctx,
    makeOwnershipFromContextMeta(ctx)
  );
  return (
    await createOauthEmbedConnection(
      ctx.params as CreateOauthEmbedConnectionPayload
    )
  ).unwrap();
};

const publicCreateEmbedToken = async (
  ctx: Context<unknown, ServiceContextMeta>
) => {
  const { createEmbedToken } = useEventLinksService(
    ctx,
    makeOwnershipFromContextMeta(ctx)
  );
  return (await createEmbedToken()).unwrap();
};

const createUserDashboardEmbedLinkToken = async (
  ctx: Context<unknown, ServiceContextMeta>
) => {
  const { createUserDashboardEmbedLinkToken } = useEventLinksService(
    ctx,
    makeOwnershipFromContextMeta(ctx)
  );
  return (await createUserDashboardEmbedLinkToken()).unwrap();
};
