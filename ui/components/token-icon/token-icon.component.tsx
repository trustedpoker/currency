import classNames from 'classnames';
import { memo } from 'react';

import { IcrcTokenMetadata } from '@dfinity/ledger-icrc';

import { useCurrencyManagerMeta } from '../../hooks/currency-manager.hook';
import { CurrencyMeta } from '../../types';
import { CKTokenSymbol, Currency, CurrencyType, Token } from '../../types/currency';
import { IsSameCKTokenSymbol, IsSameCurrency, IsSameCurrencyType, IsSameToken } from '../../utils';

export const CurrencyMetaIconComponent = memo<{ className?: string; meta: Pick<CurrencyMeta, 'isFetched' | 'icon' | 'symbol'> & { metadata?: Pick<IcrcTokenMetadata, 'name'> } }>(
  ({ meta, className }) => {
    if (!meta.icon) {
      return (
        <span
          className={classNames(
            'type-tiny font-medium',
            { 'text-animation-shimmer': !meta.isFetched },
          )}
        >
          {meta.symbol.startsWith('ck') ? meta.symbol.slice(2) : meta.symbol}
        </span>
      );
    }
    return (
      <span
        className={classNames(className, 'inline-flex', 'flex-shrink-0 flex-grow-0 rounded-[2px] overflow-hidden', {
          'size-5': !className || !className.includes('size-') || !className.includes('h-') || !className.includes('w-'),
        })}>
        <img
          src={meta.icon}
          alt={meta.metadata?.name ?? meta.symbol}
          className='object-contain w-full'
        />
      </span>
    );
  },
  (prev, next) =>
    prev.className === next.className &&
    prev.meta.icon === next.meta.icon &&
    prev.meta.symbol === next.meta.symbol &&
    prev.meta.metadata?.name === next.meta.metadata?.name
);


export const CKTokenCurrencyComponent = memo<{ className?: string; ckToken: CKTokenSymbol }>(
  ({ ckToken, className }) =>
    <CurrencyTypeIconComponent className={className} currencyType={{ Real: { CKETHToken: ckToken } }} />,
  (prev, next) =>
    IsSameCKTokenSymbol(prev.ckToken, next.ckToken) &&
    prev.className === next.className
);

export const GenericICRC1IconComponent = memo<{ className?: string; token: Token; }>(
  ({ token, className }) =>
    <CurrencyTypeIconComponent className={className} currencyType={{ Real: { GenericICRC1: token } }} />,
  (prev, next) =>
    IsSameToken(prev.token, next.token) &&
    prev.className === next.className
);

export const CurrencyIconComponent = memo<{ className?: string; currency: Currency }>(
  ({ currency, className }) => <CurrencyTypeIconComponent className={className} currencyType={{ Real: currency }} />,
  (prev, next) =>
    prev.className === next.className &&
    IsSameCurrency(prev.currency, next.currency));

export const CurrencyTypeIconComponent = memo<{ className?: string; currencyType: CurrencyType }>(
  ({ currencyType, className }) => {
    const meta = useCurrencyManagerMeta(currencyType);
    return <CurrencyMetaIconComponent className={className} meta={meta} />;
  },
  (prev, next) =>
    prev.className === next.className &&
    IsSameCurrencyType(prev.currencyType, next.currencyType)
);

