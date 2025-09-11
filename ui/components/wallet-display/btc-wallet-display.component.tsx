import { useSiwbIdentity } from 'ic-siwb-lasereyes-connector';
import { memo } from 'react';

import { ErrorComponent, ListItem, LoadingAnimationComponent } from '@zk-game-dao/ui';

import { useBTCDepositAddress } from '../../hooks/btc';

export const BTCWalletDisplayComponent = memo(() => {
  const siwb = useSiwbIdentity();
  const { data: depositBTCAddress, isPending: isFetchingDepositAddress, error } = useBTCDepositAddress();

  return (
    <>
      {isFetchingDepositAddress ?
        <LoadingAnimationComponent>Fetching deposit address</LoadingAnimationComponent> :
        (
          <>
            <ListItem>
              {depositBTCAddress}
            </ListItem>
            <p className='px-4 type-footnote text-material-medium-1'>To deposit BTC, please send your Bitcoin to the address displayed above. Ensure that you double-check the address before initiating the transaction to avoid any errors. Transactions may take some time to confirm on the Bitcoin network.</p>
          </>
        )
      }
      <ErrorComponent
        error={error}
      />
    </>
  );
});
