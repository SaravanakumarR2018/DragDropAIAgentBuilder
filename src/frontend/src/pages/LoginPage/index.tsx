import LangflowLogo from "@/assets/LangflowLogo.svg?react";
import { CustomLink } from "@/customization/components/custom-link";
import * as Form from "@radix-ui/react-form";
import { useState, useCallback } from "react";
import InputComponent from "../../components/core/parameterRenderComponent/components/inputComponent";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { SIGNIN_ERROR_ALERT } from "../../constants/alerts_constants";
import { CONTROL_LOGIN_STATE } from "../../constants/constants";
import useAlertStore from "../../stores/alertStore";
import { LoginType } from "../../types/api";
import {
  inputHandlerEventType,
  loginInputStateType,
} from "../../types/components";
import { api } from "@/controllers/API/api";
import { getURL } from "@/controllers/API/helpers/constants";
import { Cookies } from "react-cookie";
import {
  LANGFLOW_ACCESS_TOKEN,
  LANGFLOW_AUTO_LOGIN_OPTION,
  LANGFLOW_REFRESH_TOKEN,
} from "@/constants/constants";
import { setLocalStorage } from "@/utils/local-storage-util";
import useAuthStore from "@/stores/authStore";

export default function LoginPage(): JSX.Element {
  const [inputState, setInputState] =
    useState<loginInputStateType>(CONTROL_LOGIN_STATE);

  const { password, username } = inputState;
  const setErrorData = useAlertStore((state) => state.setErrorData);
  const setIsAuthenticated = useAuthStore((state) => state.setIsAuthenticated);
  const setAccessToken = useAuthStore((state) => state.setAccessToken);
  const setAutoLogin = useAuthStore((state) => state.setAutoLogin);
  const cookies = new Cookies();

  function handleInput({
    target: { name, value },
  }: inputHandlerEventType): void {
    setInputState((prev) => ({ ...prev, [name]: value }));
  }

  const signIn = useCallback(async () => {
    const user: LoginType = {
      username: username.trim(),
      password: password.trim(),
    };

    try {
      const response = await api.post(
        `${getURL("LOGIN")}`,
        new URLSearchParams({
          username: user.username,
          password: user.password,
        }).toString(),
        {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
        },
      );

      const data = response.data;
      cookies.set(LANGFLOW_ACCESS_TOKEN, data.access_token, { path: "/" });
      cookies.set(LANGFLOW_AUTO_LOGIN_OPTION, "login", { path: "/" });

      setLocalStorage(LANGFLOW_ACCESS_TOKEN, data.access_token);

      if (data.refresh_token) {
        cookies.set(LANGFLOW_REFRESH_TOKEN, data.refresh_token, {
          path: "/",
        });
      }

      setAccessToken(data.access_token);
      setIsAuthenticated(true);
      setAutoLogin(false);
    } catch (error: any) {
      const detail =
        error?.response?.data?.detail || "Failed to sign in. Please try again.";
      setErrorData({
        title: SIGNIN_ERROR_ALERT,
        list: [detail],
      });
    }
  }, [username, password, cookies, setErrorData, setAccessToken, setIsAuthenticated, setAutoLogin]);

  return (
    <Form.Root
      onSubmit={(event) => {
        if (password === "") {
          event.preventDefault();
          return;
        }
        signIn();
        const data = Object.fromEntries(new FormData(event.currentTarget));
        event.preventDefault();
      }}
      className="h-screen w-full"
    >
      <div className="flex h-full w-full flex-col items-center justify-center bg-muted">
        <div className="flex w-72 flex-col items-center justify-center gap-2">
          <LangflowLogo
            title="Langflow logo"
            className="mb-4 h-10 w-10 scale-[1.5]"
          />
          <span className="mb-6 text-2xl font-semibold text-primary">
            Sign in to Langflow
          </span>
          <div className="mb-3 w-full">
            <Form.Field name="username">
              <Form.Label className="data-[invalid]:label-invalid">
                Username <span className="font-medium text-destructive">*</span>
              </Form.Label>

              <Form.Control asChild>
                <Input
                  type="username"
                  onChange={({ target: { value } }) => {
                    handleInput({ target: { name: "username", value } });
                  }}
                  value={username}
                  className="w-full"
                  required
                  placeholder="Username"
                />
              </Form.Control>

              <Form.Message match="valueMissing" className="field-invalid">
                Please enter your username
              </Form.Message>
            </Form.Field>
          </div>
          <div className="mb-3 w-full">
            <Form.Field name="password">
              <Form.Label className="data-[invalid]:label-invalid">
                Password <span className="font-medium text-destructive">*</span>
              </Form.Label>

              <InputComponent
                onChange={(value) => {
                  handleInput({ target: { name: "password", value } });
                }}
                value={password}
                isForm
                password={true}
                required
                placeholder="Password"
                className="w-full"
              />

              <Form.Message className="field-invalid" match="valueMissing">
                Please enter your password
              </Form.Message>
            </Form.Field>
          </div>
          <div className="w-full">
            <Form.Submit asChild>
              <Button className="mr-3 mt-6 w-full" type="submit">
                Sign in
              </Button>
            </Form.Submit>
          </div>
          <div className="w-full">
            <CustomLink to="/signup">
              <Button className="w-full" variant="outline" type="button">
                Don't have an account?&nbsp;<b>Sign Up</b>
              </Button>
            </CustomLink>
          </div>
        </div>
      </div>
    </Form.Root>
  );
}
