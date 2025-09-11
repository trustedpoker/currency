import { format } from 'date-fns';

import { BigIntTimestampToDate } from '@zk-game-dao/ui';

const dateTimeFormat = `dd.MM.yyyy HH:mm`;
export const fmtDate = (dtn: Date) => format(dtn, dateTimeFormat);
export const fmt = (dtn: bigint) => fmtDate(BigIntTimestampToDate(dtn));
