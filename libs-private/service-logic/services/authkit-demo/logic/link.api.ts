import {
  CreateEventLinkPayload,
  LinkSettings,
  EventLink,
  ConnectionDefinitions,
} from '@event-inc/types';
import {
  makeHttpNetworkCall,
  matchResultAndHandleHttpError,
} from '@event-inc/utils';
import { identity } from 'ramda';
import { EmbedTokenRecord } from '@event-inc/types/embed-tokens';
import { generateId } from '@libs-private/utils';

export const createEventLinkTokenApi = async (
  headers: Record<string, string>,
  url: string,
  payload: CreateEventLinkPayload,
  secret: string
) => {
  const settings = await makeHttpNetworkCall<LinkSettings>({
    method: 'POST',
    url: `${url}/v1/settings/get`,
    headers,
  });

  const { data } = matchResultAndHandleHttpError(settings, identity);

  const isLiveSecret = secret.includes('sk_live');

  const link = await makeHttpNetworkCall<EventLink>({
    method: 'POST',
    url: `${url}/v1/event-links/create`,
    headers,
    data: {
      ...payload,
      environment: isLiveSecret ? 'live' : 'test',
      usageSource: 'demo',
    },
  });

  const { data: linkData } = matchResultAndHandleHttpError(link, identity);

  const apiBaseUrl = process.env.PICA_API_BASE_URL || "https://platform-backend.inhotel.io/v1";
  const connectionDefinitionUrl = `${apiBaseUrl}/public/connection-definitions`;

  const connectionDefinitions =
    await makeHttpNetworkCall<ConnectionDefinitions>({
      method: 'GET',
      url: `${connectionDefinitionUrl}?limit=100&skip=0`,
    });

  const { data: connectionDefinitionsData } = matchResultAndHandleHttpError(
    connectionDefinitions,
    identity
  );

  const activeConnectionDefinitionsData =
    connectionDefinitionsData?.rows?.filter((definition) => definition?.active);

  // Remove the platforms from the settings.connectedPlatforms that are not active
  const connectedPlatforms = data?.connectedPlatforms?.filter((platform) => {
    return (
      activeConnectionDefinitionsData?.find(
        (definition) => definition?._id === platform?.connectionDefinitionId
      ) && platform?.active
    );
  });

  // Filter out the connectedPlatforms based on the secret. If the secret is live, only return the live platforms otherwise return all the platforms
  const connectedPlatformsFiltered = connectedPlatforms?.filter(
    (platform) =>
      isLiveSecret
        ? platform?.environment === 'live'
        : platform?.environment === 'test' || !platform?.environment
  );

  const sessionId = await generateId('session_id');

  const tokenPayload = {
    linkSettings: {
      connectedPlatforms: connectedPlatformsFiltered ?? [],
      eventIncToken: linkData?.token,
    },
    environment: isLiveSecret ? 'live' : 'test',
    expiresAt: new Date().getTime() + 5 * 1000 * 60,
    sessionId,
    features: data?.features
  };

  const token = await makeHttpNetworkCall<EmbedTokenRecord>({
    method: 'POST',
    url: `${url}/v1/embed-tokens/create`,
    headers,
    data: tokenPayload,
  });

  const { data: embedToken } = matchResultAndHandleHttpError(token, identity);

  return embedToken;
};
