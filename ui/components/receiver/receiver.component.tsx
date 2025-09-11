import { CopiableTextComponent, ListItem } from '@zk-game-dao/ui';
import React, { memo } from 'react';

import { CurrencyReceiver } from '../../types/currency';

export const ReceiverComponent = memo<{ receiver: CurrencyReceiver }>(
  ({ receiver }) => {
    if (!receiver) return null;
    if ("principal" in receiver)
      return (
        <ListItem
          rightLabel={<CopiableTextComponent text={receiver.principal.toText()} />}
        >
          Receiver Principal
        </ListItem>
      );
    if ("accountIdentifier" in receiver)
      return (
        <ListItem
          rightLabel={
            <CopiableTextComponent text={receiver.accountIdentifier.toHex()} />
          }
        >
          Receiver Account ID
        </ListItem>
      );
    return null;
  },
);
