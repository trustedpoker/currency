import { ErrorComponent, FormComponent, Image, Interactable, List, Modal, TitleTextComponent } from '@zk-game-dao/ui';
import { memo, useMemo, useState } from 'react';

import { NetworkGuardComponent } from '../../../components/network-guard/network-guard.component';
import { Web3AuthLoginProvider, SocialLoginProviders, useAuth } from '../../types';
import { LoginProviderListItemComponent } from '../login-provider/login-provider-list-item.component';
import { SWIBLogins } from './swib-logins.component';

const SocialsComponent = memo<{
  onClose(): void;
  isLoggingIn: boolean;
  loginFactory(loginProvider: Web3AuthLoginProvider): () => Promise<void>;
}>(({ onClose, isLoggingIn, loginFactory }) => {
  const [isShowingMore, setShowingMore] = useState(false);

  const [email, setEmail] = useState<string | undefined>();

  const shownLoginProviders = useMemo(
    () =>
      isShowingMore ? SocialLoginProviders : SocialLoginProviders.slice(0, 5),
    [isShowingMore],
  );

  return (
    <div className="gap-3 flex flex-col justify-center">

      {/* Email login */}
      <FormComponent
        fields={[{ label: "Email", type: "email", name: "email" }]}
        values={[email]}
        onChange={([email]) => setEmail(email as string)}
        onCancel={onClose}
        isLoading={isLoggingIn}
        onConfirm={loginFactory({
          type: "email_passwordless",
          email: email ?? "",
        })}
      />

      <List>
        {shownLoginProviders.map((loginProvider) => (
          <LoginProviderListItemComponent
            key={loginProvider}
            loginProvider={loginProvider}
            login={loginFactory({ type: loginProvider })}
          />
        ))}
      </List>

      {!isShowingMore && (
        <Interactable
          className="text-material-main-3 flex flex-row type-button-3 justify-center items-center"
          onClick={() => setShowingMore(!isShowingMore)}
        >
          Show more
          <Image
            src="/icons/chevron-down-white.svg"
            type="svg"
            className="w-2 opacity-30 ml-2"
            alt="Show more"
          />
        </Interactable>
      )}
    </div>
  );
});


export const SignupModalComponent = memo<{ onClose(): void }>(({ onClose }) => {
  const { loginFactory, error, isLoggingIn } = useAuth();

  return (
    <Modal open onClose={onClose}>
      <TitleTextComponent title="Sign in" text="Choose a method to sign in" />

      <NetworkGuardComponent network="btc">
        <SWIBLogins />
      </NetworkGuardComponent>

      <NetworkGuardComponent network="ic">
        <SocialsComponent
          onClose={onClose}
          isLoggingIn={!!isLoggingIn}
          loginFactory={loginFactory}
        />

        <ErrorComponent error={error} className="mb-4" />
      </NetworkGuardComponent>
    </Modal>
  );
});
