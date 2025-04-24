import { Context } from 'moleculer';
import { Ownership, Services } from '@libs-private/data-models';
import {
  BResult,
  ConnectionDefinitions,
  ConnectionRecord,
  EventAccessRecords,
} from '@event-inc/types';
import { useGenericCRUDService } from '../genericCRUD';
import {
  CreateEmbedConnectionPayload,
  CreateEventLinkPayload,
  CreateOauthEmbedConnectionPayload,
  EventLink,
} from '@event-inc/types/links';
import { generateEventLinkRecord } from '@libs-private/service-logic/generators/events/eventLink';
import {
  makeHttpNetworkCall,
  matchResultAndHandleHttpError,
  resultErr,
  resultOk,
} from '@event-inc/utils';
import { useSettingsService } from '../settings/useSettingsService';
import { identity } from 'ramda';
import jwt from 'jsonwebtoken';
import { useEventAccessService } from '../events/useEventAccessService';
import _ from 'lodash';
import { v4 as uuidv4 } from 'uuid';
import { generateEmbedTokensRecord } from '@libs-private/service-logic/generators/embedTokens';
import { generateId } from '@libs-private/utils';

const GET_EVENT_ACCESS_RECORD_URL = process.env.CONNECTIONS_API_BASE_URL + 'v1/event-access';
const CREATE_CONNECTION_URL = process.env.CONNECTIONS_API_BASE_URL + 'v1/connections';
const CREATE_OAUTH_CONNECTION_URL = process.env.CONNECTIONS_API_BASE_URL + 'v1/oauth';
const LIST_CONNECTION_DEFINITIONS_URL = process.env.CONNECTIONS_API_BASE_URL + 'v1/public/connection-definitions';

const SERVICE_NAME = Services.EventLinks;

export const useEventLinksService = (ctx: Context, ownership: Ownership) => {
  const {
    create: _create,
    find,
    updateById,
  } = useGenericCRUDService(ctx, SERVICE_NAME, ownership, {
    DISABLE_ADDING_OWNERSHIP_CHECK: true,
  });

  return {
    async create({
      identity,
      identityType,
      group,
      label,
      ttl = 2 * 1000 * 60 * 60,
      environment = 'live',
      usageSource,
    }: CreateEventLinkPayload): Promise<
      BResult<EventLink, 'service', unknown>
    > {
      const link = await generateEventLinkRecord({
        ttl,
        ownership,
        environment,
        usageSource,
        identity,
        identityType,
        group,
        label,
      });

      return await _create<EventLink>('ln', link);
    },
    async createEmbedConnection({
      connectionDefinitionId,
      linkToken,
      authFormData,
      type,
    }: CreateEmbedConnectionPayload): Promise<
      BResult<ConnectionRecord, 'service', unknown>
    > {
      const linkResult = await find<EventLink>({
        query: {
          token: linkToken,
        },
      });

      const links = linkResult.unwrap();

      if (links.length === 0) {
        return resultErr<'service'>(
          false,
          'service_4004',
          'Link not found',
          'buildable-core',
          false
        );
      }

      const link = links[0];

      if (link.expiresAt <= Date.now()) {
        return resultErr<'service'>(
          false,
          'service_4000',
          'This link token has expired',
          'buildable-core',
          false
        );
      }

      const contextMetadata = ctx.meta as any;
      const headers = contextMetadata.request.headers;

      try {
        const { listAccessKeys } = useEventAccessService(ctx, link.ownership);
        const eventAccessRecords = await listAccessKeys({
          query: {
            key:
              link?.environment === 'test'
                ? process.env.DEFAULT_TEST_ACCESS_KEY
                : process.env.DEFAULT_LIVE_ACCESS_KEY,
          },
        });
        const recordsList = matchResultAndHandleHttpError(
          eventAccessRecords,
          identity
        );

        const connection = await makeHttpNetworkCall<ConnectionRecord>({
          url: CREATE_CONNECTION_URL,
          method: 'POST',
          headers: {
            'x-pica-secret':
              headers['x-pica-secret'] ??
              recordsList?.rows?.[0]?.accessKey,
          },
          data: {
            active: true,
            connectionDefinitionId,
            authFormData,
            identity: link?.identity,
            identityType: link?.identityType,
            name: link?.label,
            group: link?.group,
          },
        });

        const result = matchResultAndHandleHttpError(connection, identity);

        await updateById(link._id, {
          expiresAt: Date.now(),
          updatedAt: Date.now(),
          type,
        });

        return resultOk(result.data);
      } catch (error) {
        return resultErr<'service'>(
          false,
          'service_4000',
          error?.data?.data?.error || 'Invalid connection credentials',
          'buildable-core',
          false
        );
      }
    },

    async createOauthEmbedConnection({
      connectionDefinitionId,
      linkToken,
      clientId,
      code,
      redirectUri,
      type,
      formData,
      additionalData,
    }: CreateOauthEmbedConnectionPayload): Promise<
      BResult<ConnectionRecord, 'service', unknown>
    > {
      ctx.broker.logger.error('[createOauthEmbedConnection] STARTED with params:', { 
        connectionDefinitionId, 
        linkToken, 
        clientId: clientId ? '[REDACTED]' : undefined,
        hasCode: !!code,
        redirectUri,
        type,
        hasFormData: !!formData,
        hasAdditionalData: !!additionalData
      });

      const linkResult = await find<EventLink>({
        query: {
          token: linkToken,
        },
      });

      const links = linkResult.unwrap();
      ctx.broker.logger.error('[createOauthEmbedConnection] Links found:', { count: links.length });

      if (links.length === 0) {
        ctx.broker.logger.error('[createOauthEmbedConnection] ERROR: Link not found for token');
        return resultErr<'service'>(
          false,
          'service_4004',
          'Link not found',
          'buildable-core',
          false
        );
      }

      const link = links[0];
      ctx.broker.logger.error('[createOauthEmbedConnection] Link found:', { 
        id: link._id,
        expiresAt: link.expiresAt,
        currentTime: Date.now(),
        isExpired: link.expiresAt <= Date.now(),
        environment: link.environment,
        usageSource: link.usageSource
      });

      if (link.expiresAt <= Date.now()) {
        ctx.broker.logger.error('[createOauthEmbedConnection] ERROR: Link token expired');
        return resultErr<'service'>(
          false,
          'service_4000',
          'This link token has expired',
          'buildable-core',
          false
        );
      }

      const contextMetadata = ctx.meta as any;
      const headers = contextMetadata.request.headers;
      ctx.broker.logger.error('[createOauthEmbedConnection] Headers:', { 
        hasXPicaSecret: !!headers['x-pica-secret'],
        headerKeys: Object.keys(headers)
      });

      try {
        ctx.broker.logger.error('[createOauthEmbedConnection] Getting access keys for ownership:', link.ownership);
        const { listAccessKeys } = useEventAccessService(ctx, link.ownership);
        const eventAccessRecords = await listAccessKeys({
          query: {
            key:
              link?.environment === 'test'
                ? process.env.DEFAULT_TEST_ACCESS_KEY
                : process.env.DEFAULT_LIVE_ACCESS_KEY,
          },
        });
        
        ctx.broker.logger.error('[createOauthEmbedConnection] Access key query result received');
        const recordsList = matchResultAndHandleHttpError(
          eventAccessRecords,
          identity
        );
        
        ctx.broker.logger.error('[createOauthEmbedConnection] Access records:', { 
          hasRecords: !!recordsList, 
          hasRows: !!recordsList?.rows,
          rowCount: recordsList?.rows?.length,
          firstRowHasAccessKey: !!recordsList?.rows?.[0]?.accessKey
        });

        let secret = headers['x-pica-secret'];

        if (!secret || secret === 'redacted') {
          secret = recordsList?.rows?.[0]?.accessKey;
          ctx.broker.logger.error('[createOauthEmbedConnection] Using default access key');
        } else {
          ctx.broker.logger.error('[createOauthEmbedConnection] Using header access key');
        }

        // Log the URL we're about to call
        const apiUrl = `${CREATE_OAUTH_CONNECTION_URL}/${type}`;
        ctx.broker.logger.error('[createOauthEmbedConnection] Making API call to:', apiUrl);
        
        // Prepare the data payload for logging (without sensitive values)
        const safeDataForLogging = {
          __isEngineeringAccount__: link?.usageSource === 'user-dashboard',
          hasClientId: !!clientId,
          payload: {
            hasCode: !!code,
            hasRedirectUri: !!redirectUri,
            hasFormData: !!formData,
            hasAdditionalData: !!additionalData
          },
          type,
          connectionDefinitionId,
          identity: link?.identity,
          identityType: link?.identityType,
          name: link?.label,
          group: link?.group
        };
        
        ctx.broker.logger.error('[createOauthEmbedConnection] HTTP request data:', safeDataForLogging);

        const connection = await makeHttpNetworkCall<ConnectionRecord>({
          url: apiUrl,
          method: 'POST',
          headers: {
            'x-pica-secret': secret,
          },
          data: {
            __isEngineeringAccount__:
              link?.usageSource === 'user-dashboard' ? true : false,
            clientId,
            payload: {
              code,
              redirectUri,
              formData,
              additionalData,
            },
            type,
            connectionDefinitionId,
            identity: link?.identity,
            identityType: link?.identityType,
            name: link?.label,
            group: link?.group,
          },
        });

        ctx.broker.logger.error('[createOauthEmbedConnection] API call completed, processing result');
        const result = matchResultAndHandleHttpError(connection, identity);
        ctx.broker.logger.error('[createOauthEmbedConnection] API result processed:', { 
          success: !!result,
          hasData: !!result?.data
        });

        await updateById(link._id, {
          expiresAt: Date.now(),
          updatedAt: Date.now(),
          type,
        });
        ctx.broker.logger.error('[createOauthEmbedConnection] Link updated successfully');

        return resultOk(result.data);
      } catch (error) {
        // Log the full error object structure to debug
        ctx.broker.logger.error('[createOauthEmbedConnection] ERROR occurred:', error);
        
        // Log specific error properties that might help diagnosis
        ctx.broker.logger.error('[createOauthEmbedConnection] ERROR details:', {
          errorMessage: error?.message,
          errorName: error?.name,
          errorStack: error?.stack,
          errorData: error?.data,
          errorDataData: error?.data?.data,
          errorDataDataError: error?.data?.data?.error,
          isAxiosError: error?.isAxiosError,
          responseStatus: error?.response?.status,
          responseData: error?.response?.data
        });

        const errorMessage = error?.data?.data?.error || 'Invalid connection credentials';
        ctx.broker.logger.error('[createOauthEmbedConnection] Returning error message:', errorMessage);
        
        return resultErr<'service'>(
          false,
          'service_4000',
          errorMessage,
          'buildable-core',
          false
        );
      }
    },

    async createEmbedToken(): Promise<BResult<any, 'service', unknown>> {
      ctx.broker.logger.error('[createEmbedToken] Starting createEmbedToken method');
      const contextMetadata = ctx.meta as any;
      const headers = contextMetadata.request.headers;

      ctx.broker.logger.warn('[createEmbedToken] Starting createEmbedToken method');
      ctx.broker.logger.warn('[createEmbedToken] ENGINEERING_ACCOUNT_BUILDABLE_ID:', process.env.ENGINEERING_ACCOUNT_BUILDABLE_ID);
      
      // Get the settings for the engineering account
      const { get } = useSettingsService(ctx, {
        buildableId: process.env.ENGINEERING_ACCOUNT_BUILDABLE_ID,
      });
      const settingsResult = await get();
      const settings = settingsResult.unwrap();
      ctx.broker.logger.warn('[createEmbedToken] Settings retrieved:', JSON.stringify(settings, null, 2));

      // Get the event access records
      ctx.broker.logger.warn('[createEmbedToken] Getting event access records with x-pica-secret:', headers['x-pica-secret']);
      const eventAccessRecords = await makeHttpNetworkCall<EventAccessRecords>({
        url: GET_EVENT_ACCESS_RECORD_URL,
        method: 'GET',
        headers: {
          'x-pica-secret': headers['x-pica-secret'],
          'x-pica-redaction': false,
        },
        params: {
          accessKey: headers['x-pica-secret'],
        },
      });

      const { data: records } = matchResultAndHandleHttpError(
        eventAccessRecords,
        identity
      );
      ctx.broker.logger.warn('[createEmbedToken] Event access records retrieved:', JSON.stringify(records?.rows, null, 2));

      // Generate a link record
      const link = await generateEventLinkRecord({
        ttl: 2 * 1000 * 60 * 60,
        ownership: records?.rows?.[0]?.ownership,
        environment: headers['x-pica-secret'].startsWith('sk_test')
          ? 'test'
          : 'live',
        usageSource: 'user-dashboard',
      });

      const { create: createLink } = useGenericCRUDService(
        ctx,
        SERVICE_NAME,
        records?.rows?.[0]?.ownership,
        {
          DISABLE_ADDING_OWNERSHIP_CHECK: true,
        }
      );

      const token = await createLink<EventLink>('ln', link);
      ctx.broker.logger.warn('[createEmbedToken] Link token created');

      // Get the link token
      const linkToken = matchResultAndHandleHttpError(token, identity);

      let url = LIST_CONNECTION_DEFINITIONS_URL;
      ctx.broker.logger.warn('[createEmbedToken] Fetching connection definitions from:', url);

      // Get all connection definitions
      const connectionDefinitions =
        await makeHttpNetworkCall<ConnectionDefinitions>({
          url: `${url}?limit=100&skip=0&active=true`,
          method: 'GET',
        });
      const { data: activeConnectionDefinitionsData } =
        matchResultAndHandleHttpError(connectionDefinitions, identity);
      ctx.broker.logger.warn('[createEmbedToken] Connection definitions count:', activeConnectionDefinitionsData?.rows?.length);

      // Remove the platforms from the settings.connectedPlatforms that are not active
      const connectedPlatforms = settings?.connectedPlatforms?.filter(
        (platform) => {
          return (
            activeConnectionDefinitionsData?.rows?.find(
              (definition) =>
                definition?._id === platform?.connectionDefinitionId
            ) && platform?.active
          );
        }
      );
      ctx.broker.logger.warn('[createEmbedToken] Connected platforms count:', connectedPlatforms?.length);

      // Filter the connected platforms based on the environment
      const connectedPlatformsFiltered = connectedPlatforms?.filter(
        (platform) =>
          headers['x-pica-secret'].startsWith('sk_test')
            ? platform?.environment === 'test'
            : platform?.environment === 'live'
      );
      ctx.broker.logger.warn('[createEmbedToken] Filtered connected platforms count:', connectedPlatformsFiltered?.length);

      const sessionId = await generateId('session_id');
      ctx.broker.logger.warn('[createEmbedToken] Generated sessionId:', sessionId);

      const tokenPayload = {
        linkSettings: {
          connectedPlatforms: connectedPlatformsFiltered ?? [],
          eventIncToken: linkToken?.token,
        },
        ttl: 5 * 60 * 1000,
        environment: headers['x-pica-secret'].startsWith('sk_test')
          ? 'test'
          : 'live',
        features: settings?.features,
        sessionId
      };
      ctx.broker.logger.warn('[createEmbedToken] Token payload prepared');

      const embedToken = await generateEmbedTokensRecord(tokenPayload);

      const { create: createEmbedToken } = useGenericCRUDService(
        ctx,
        Services.EmbedTokens,
        records?.rows?.[0]?.ownership,
        {
          DISABLE_ADDING_OWNERSHIP_CHECK: true,
        }
      );

      const tokenResult = await createEmbedToken('embed_tk', embedToken);
      const tokenData = matchResultAndHandleHttpError(tokenResult, identity);
      ctx.broker.logger.warn('[createEmbedToken] Embed token created successfully');

      return resultOk(tokenData);
    },

    async createUserDashboardEmbedLinkToken(): Promise<
      BResult<any, 'service', unknown>
    > {
      const contextMetadata = ctx.meta as any;
      const headers = contextMetadata.request.headers;

      ctx.broker.logger.warn('[createUserDashboardEmbedLinkToken] Starting method');
      
      // Decode the JWT token
      const authorization = headers['authorization'];
      const authToken = authorization.split(' ')[1];
      const decoded = jwt.decode(authToken, { complete: true });
      ctx.broker.logger.warn('[createUserDashboardEmbedLinkToken] JWT decoded payload:', JSON.stringify(decoded?.payload, null, 2));

      // Get the settings for the engineering account
      ctx.broker.logger.warn('[createUserDashboardEmbedLinkToken] ENGINEERING_ACCOUNT_BUILDABLE_ID:', process.env.ENGINEERING_ACCOUNT_BUILDABLE_ID);
      const { get } = useSettingsService(ctx, {
        buildableId: process.env.ENGINEERING_ACCOUNT_BUILDABLE_ID,
      });
      const settingsResult = await get();
      const settings = settingsResult.unwrap();
      ctx.broker.logger.warn('[createUserDashboardEmbedLinkToken] Settings retrieved:', JSON.stringify(settings, null, 2));

      // Get the event access records
      ctx.broker.logger.warn('[createUserDashboardEmbedLinkToken] Getting event access with key in the payload:', `${decoded?.payload}`);
      const eventAccessRecords = await makeHttpNetworkCall<EventAccessRecords>({
        url: GET_EVENT_ACCESS_RECORD_URL,
        method: 'GET',
        headers: {
          // @ts-ignore
          'x-pica-secret': `sk_test${decoded?.payload?.pointers?.[0]}`,
          'x-pica-redaction': false,
        },
        params: {
          // @ts-ignore
          accessKey: `sk_test${decoded?.payload?.pointers?.[0]}`,
        },
      });

      const { data: records } = matchResultAndHandleHttpError(
        eventAccessRecords,
        identity
      );
      ctx.broker.logger.warn('[createUserDashboardEmbedLinkToken] Event access records retrieved:', JSON.stringify(records?.rows, null, 2));

      // Generate a link record
      const link = await generateEventLinkRecord({
        ttl: 2 * 1000 * 60 * 60,
        ownership: records?.rows?.[0]?.ownership,
        environment: 'test',
        usageSource: 'user-dashboard',
      });
      ctx.broker.logger.warn('[createUserDashboardEmbedLinkToken] Link record generated');

      const { create: createLink } = useGenericCRUDService(
        ctx,
        SERVICE_NAME,
        records?.rows?.[0]?.ownership,
        {
          DISABLE_ADDING_OWNERSHIP_CHECK: true,
        }
      );

      const token = await createLink<EventLink>('ln', link);
      ctx.broker.logger.warn('[createUserDashboardEmbedLinkToken] Link created');

      // Get the link token
      const linkToken = matchResultAndHandleHttpError(token, identity);

      let url = LIST_CONNECTION_DEFINITIONS_URL;
      ctx.broker.logger.warn('[createUserDashboardEmbedLinkToken] Fetching connection definitions from:', url);

      // Get all connection definitions
      const connectionDefinitions =
        await makeHttpNetworkCall<ConnectionDefinitions>({
          url: `${url}?limit=100&skip=0&active=true`,
          method: 'GET',
        });
      const { data: activeConnectionDefinitionsData } =
        matchResultAndHandleHttpError(connectionDefinitions, identity);
      ctx.broker.logger.warn('[createUserDashboardEmbedLinkToken] Connection definitions count:', activeConnectionDefinitionsData?.rows?.length);

      // Remove the platforms from the settings.connectedPlatforms that are not active and also remove the platforms that have environment as live
      const connectedPlatforms = settings?.connectedPlatforms?.filter(
        (platform) => {
          return (
            activeConnectionDefinitionsData?.rows?.find(
              (definition) =>
                definition?._id === platform?.connectionDefinitionId
            ) && platform?.active && platform?.environment !== 'live'
          );
        }
      );
      ctx.broker.logger.warn('[createUserDashboardEmbedLinkToken] Filtered connected platforms count:', connectedPlatforms?.length);

      const sessionId = await generateId('session_id');
      ctx.broker.logger.warn('[createUserDashboardEmbedLinkToken] Generated sessionId:', sessionId);

      const tokenPayload = {
        linkSettings: {
          connectedPlatforms: connectedPlatforms ?? [],
          eventIncToken: linkToken?.token,
        },
        ttl: 5 * 60 * 1000,
        environment: 'test',
        features: settings?.features,
        sessionId,
      };
      ctx.broker.logger.warn('[createUserDashboardEmbedLinkToken] Token payload prepared');

      const embedToken = await generateEmbedTokensRecord(tokenPayload);

      const { create: createEmbedToken } = useGenericCRUDService(
        ctx,
        Services.EmbedTokens,
        records?.rows?.[0]?.ownership,
        {
          DISABLE_ADDING_OWNERSHIP_CHECK: true,
        }
      );

      const tokenResult = await createEmbedToken('embed_tk', embedToken);
      const tokenData = matchResultAndHandleHttpError(tokenResult, identity);
      ctx.broker.logger.warn('[createUserDashboardEmbedLinkToken] Embed token created successfully');

      return resultOk(tokenData);
    },

    find,
    updateById,
  };
};
