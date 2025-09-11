import { memo, useMemo, useRef } from 'react';

import MempoolClient from '@mempool/mempool.js';
import { Tx } from '@mempool/mempool.js/lib/interfaces/bitcoin/transactions';
import { List, ListItem, LoadingAnimationComponent, useQuery } from '@zk-game-dao/ui';

import { CurrencyComponent } from '../currency';
import { fmtDate } from '../../hooks/date-format';
import classNames from 'classnames';

const bufferConfirmations = 2;

const BTCWalletTransaction = memo<Tx & { btcAddress: string; currentHeight: number; requiredConfirmations: number }>(
  ({ txid, status, vout, fee, btcAddress, currentHeight, requiredConfirmations }) => {
    const amount = useMemo((): bigint =>
      vout.filter(item => item.scriptpubkey_address === btcAddress)
        .reduce((acc, item) => acc + BigInt(item.value || 0), BigInt(0)),
      [btcAddress, vout]);

    const confirmations = useMemo(() => {
      if (!status.confirmed || status.block_height == null) return 0;
      return currentHeight - status.block_height + 1;
    }, [status.confirmed, status.block_height, currentHeight]);

    const isConfirmed = useMemo(() => {
      if (!status.confirmed) return false;
      return confirmations >= requiredConfirmations + bufferConfirmations;
    }, [status.confirmed, confirmations, requiredConfirmations]);

    if (!amount) return null;

    return (
      <List
        className="mb-2"
        label={status.block_time && fmtDate(new Date(status.block_time))}
        ctas={[
          {
            label: 'View on Mempool',
            href: `https://mempool.space/tx/${txid}`,
            isOutLink: true,
          }
        ]}
      >
        <ListItem rightLabel={<span className='truncate w-full overflow-hidden max-w-[250px]'>{txid}</span>}>
          Transaction
        </ListItem>
        <ListItem rightLabel={isConfirmed ? <span className='text-green-500'>Confirmed</span> : <LoadingAnimationComponent variant="shimmer">Processing</LoadingAnimationComponent>}>
          Status
        </ListItem>
        <ListItem rightLabel={<CurrencyComponent currencyType={{ Real: { BTC: null } }} currencyValue={BigInt(fee)} />}>
          Fee
        </ListItem>
        <ListItem
          rightLabel={
            <>
              {amount > 0 ? '+' : ''}
              <CurrencyComponent
                currencyType={{ Real: { BTC: null } }}
                currencyValue={amount}
                className={classNames({
                  'text-green-500': amount > 0,
                  'text-red-500': amount < 0,
                })}
              />
            </>
          }>
          Balance Update
        </ListItem>
      </List>
    );
  },
  (prevProps, nextProps) => (
    prevProps.txid === nextProps.txid &&
    prevProps.status.confirmed === nextProps.status.confirmed &&
    prevProps.vin.length === nextProps.vin.length &&
    prevProps.vout.length === nextProps.vout.length &&
    prevProps.currentHeight === nextProps.currentHeight
  )
);

export const BTCWalletTransactions = memo<{ btcAddress: string; requiredConfirmations: number }>(({ btcAddress, requiredConfirmations }) => {
  const mempoolClient = useRef(MempoolClient({
    hostname: 'mempool.space'
  }));

  const { data, isPending } = useQuery({
    queryKey: ['btc-transactions', btcAddress],
    queryFn: async () => {
      const [txs, currentHeight] = await Promise.all([
        mempoolClient.current.bitcoin.addresses.getAddressTxs({ address: btcAddress }),
        fetch('https://mempool.space/api/blocks/tip/height').then(res => res.json())
      ]);
      return { txs, currentHeight };
    }
  });

  if (isPending) return <LoadingAnimationComponent>Loading transactions</LoadingAnimationComponent>;

  if (!data || data.txs.length === 0) return null;

  return (
    <>
      {data.txs.map((tx) => (
        <BTCWalletTransaction
          key={tx.txid}
          {...tx}
          requiredConfirmations={requiredConfirmations}
          btcAddress={btcAddress}
          currentHeight={data.currentHeight}
        />
      ))}
    </>
  );
});
