import classNames from 'classnames';
import { animate } from 'framer-motion';
import { memo, useEffect, useMemo, useRef } from 'react';

import { useCurrencyManagerMeta } from '../../hooks/currency-manager.hook';
import { CurrencyMeta, CurrencyType } from '../../types';
import { TokenAmountToString } from '../../utils/token-amount-conversion';
import { CurrencyMetaIconComponent, CurrencyTypeIconComponent } from '../token-icon/token-icon.component';
import { IsSameCurrencyType } from '../../utils';

export type CryptoCoinValue = {
  currencyValue?: bigint;
  currencyType: CurrencyType;
};

export type CurrencyComponentInnerProps = CryptoCoinValue & {
  className?: string;
  size?: "medium" | "big" | "small";
  hideSymbol?: boolean;
  reverse?: boolean;
  forceFlex?: boolean;
};

const CountDecimals = (value: number) => {
  if (Math.floor(value.valueOf()) === value.valueOf()) return 0;
  return value.toString().split(".")[1]?.length || 0;
};

export const CurrencyComponentInner = memo<CurrencyComponentInnerProps & Pick<CurrencyMeta, 'decimals' | 'symbol' | 'isFetched' | 'icon' | "renderedDecimalPlaces">>(
  ({
    hideSymbol: hideToken,
    size = "medium",
    reverse = false,
    className,
    currencyValue,
    currencyType,
    forceFlex,
    ...meta
  }) => {
    const amount = useMemo(
      () =>
        !currencyValue
          ? "0"
          : TokenAmountToString(currencyValue, meta),
      [currencyValue, meta],
    );
    const ref = useRef<HTMLSpanElement>(null);

    useEffect(() => {
      if (meta.decimals > 9) {
        if (!ref.current) return;
        ref.current.textContent = amount;
        return;
      }
      if (amount.toUpperCase().indexOf("K") !== -1) {
        if (ref.current)
          ref.current.textContent = amount;
        return;
      }

      const from = parseFloat(ref.current?.textContent || amount + "");
      const to = parseFloat(amount + "");
      const distance = Math.abs(from - to);
      if (isNaN(from) || isNaN(to)) return;
      // Somehow sometimes currencies can be infinity
      if (to === Infinity || to === -Infinity) {
        if (!ref.current) return;
        ref.current.textContent = "Infinity";
        return;
      }
      const controls = animate(from, to, {
        duration: Math.min(1, Math.max(distance / 500, 9)) * 0.3,
        ease: "anticipate",
        onUpdate(value) {
          if (!ref.current) return;
          ref.current.textContent = value.toFixed(CountDecimals(to));
        },
        onComplete() {
          if (!ref.current) return;
          ref.current.textContent = to.toString();
        },
      });
      return () => controls?.stop();
    }, [amount]);

    return (
      <div
        className={classNames(
          className,
          forceFlex ? 'flex' : 'inline-flex',
          "justify-center items-center shrink-0",
          {
            'gap-1': size === "small",
            'gap-2': size === "medium" || size === "big"
          },
          reverse ? "flex-row-reverse" : "flex-row",
        )}
      >
        {!hideToken && (
          <CurrencyMetaIconComponent
            className={classNames(forceFlex ? 'flex' : 'inline-flex', {
              "w-[24px] h-[24px]": size === "medium",
              "w-[32px] h-[32px]": size === "big",
              "w-[12px] h-[12px] scale-[1.5]": size === "small",
            })}
            meta={meta}
          />
        )}
        <span
          ref={ref}
          className={classNames('flex', {
            "type-header": size === "big",
            "type-button-2": size === "medium",
            "type-button-3": size === "small",
          })}
        />
      </div >
    );
  },
  (prevProps, nextProps) => (
    prevProps.hideSymbol === nextProps.hideSymbol &&
    prevProps.size === nextProps.size &&
    prevProps.reverse === nextProps.reverse &&
    prevProps.forceFlex === nextProps.forceFlex &&
    prevProps.className === nextProps.className &&
    prevProps.currencyValue === nextProps.currencyValue &&
    IsSameCurrencyType(prevProps.currencyType, nextProps.currencyType) &&
    prevProps.decimals === nextProps.decimals &&
    prevProps.renderedDecimalPlaces === nextProps.renderedDecimalPlaces &&
    prevProps.symbol === nextProps.symbol &&
    prevProps.isFetched === nextProps.isFetched &&
    prevProps.icon === nextProps.icon
  )
);

const InlineCurrencyComponentInner = memo<CurrencyComponentInnerProps>((props) => {
  const _meta = useCurrencyManagerMeta(props.currencyType);
  // Find the shortest alternative
  const meta = useMemo(() => {
    if (!_meta.alternatives || !props.currencyValue) return _meta;
    const renderedMain = TokenAmountToString(props.currencyValue, _meta);
    return Object.values(_meta.alternatives).find((alternative) => {
      const renderedAlternative = TokenAmountToString(
        props.currencyValue ?? 0n,
        alternative,
      );
      return (
        renderedMain.length > renderedAlternative.length ||
        (renderedMain.length === renderedAlternative.length &&
          alternative.decimals < _meta.decimals)
      );
    }) || _meta;
  }, [_meta, props.currencyValue]);
  return <CurrencyComponentInner {...props} {...meta} />;
});

export type CurrencyComponentProps = CurrencyComponentInnerProps & {
  variant?: "inline" | "chip";
  forceFlex?: boolean;
};

export const CurrencyComponent = memo<CurrencyComponentProps>(
  ({ className, variant = "inline", forceFlex = false, ...props }) =>
    variant === "inline" ? (
      <InlineCurrencyComponentInner {...props} forceFlex={forceFlex} className={className} />
    ) : (
      <div
        className={classNames(
          "inline-flex flex-row items-center material p-2 rounded-full",
          className,
        )}
      >
        <InlineCurrencyComponentInner {...props} />
      </div>
    ),
);
