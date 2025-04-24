import axios from 'axios';
import { get } from 'lodash';

export const cleanIdPath = (idPath: string) => idPath.replace('_.', '');

export const getIdValueFromPath = (payload: unknown, idPath: string) => {
  if (idPath.startsWith('_.')) return get(payload, cleanIdPath(idPath));
  return idPath;
};

export const buildableSlugify = (text: string): string =>
  text
    .trim()
    .replace(
      /([\u2700-\u27BF]|[\uE000-\uF8FF]|\uD83C[\uDC00-\uDFFF]|\uD83D[\uDC00-\uDFFF]|[\u2011-\u26FF]|\uD83E[\uDD10-\uDDFF])/g,
      ''
    )
    .replace(/\s+/g, ' ')
    .replace(/[^a-zA-Z0-9_]/g, '-')
    .toLowerCase();

export const generateKey = ({
  entity,
  type,
  group,
  label,
  pipelineSourceType,
  pipelineSourceGroup,
  pipelineDestinationType,
  pipelineDestinationGroup,
}: {
  entity: 'source' | 'destination' | 'pipeline' | 'event_access';
  type?: any;
  group?: string;
  label?: string;
  pipelineSourceType?: any;
  pipelineSourceGroup?: string;
  pipelineDestinationType?: any;
  pipelineDestinationGroup?: string;
}) => {
  const keyComponents: Array<string> = [entity];
  const separator = '::';

  const timestamp = Buffer.from(new Date().getTime().toString()).toString(
    'base64url'
  );

  const map = {
    source: () => [type, group],
    destination: () => [type, group],
    pipeline: () => [
      pipelineSourceType,
      pipelineSourceGroup,
      pipelineDestinationType,
      pipelineDestinationGroup,
      timestamp,
    ],
    event_access: () => [type, group],
    default: () => {
      throw new Error('Invalid generateKey entity type');
    },
  };

  const finalizedKeyComponents = keyComponents.concat(
    (map[entity] || map['default'])()
  );

  return finalizedKeyComponents.join(separator);
};

export const generateId = async (prefix: string) => {
  const apiBaseUrl = process.env.PICA_API_BASE_URL || "https://platform-backend.inhotel.io/v1";

  try {
    const response = await axios.get<{
      id: string
    }>(
      `${apiBaseUrl}/public/generate-id/${prefix}`
    );

    const id = response?.data?.id;

    return id;
  } catch (error) {
    throw new Error('Failed to generate id from api');
  }
}
