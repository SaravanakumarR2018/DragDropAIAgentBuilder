import type { UseMutationResult } from "@tanstack/react-query";
import type { AxiosResponse } from "axios";
import type { useMutationFunctionType } from "@/types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

type VariableCategory = (typeof VALID_CATEGORIES)[number];

interface PostGlobalVariablesParams {
  name: string;
  value: string;
  type?: string;
  default_fields?: string[];
  category?: VariableCategory;
}

interface PostGlobalVariablesResponse {
  name: string;
  id: string;
  type: string;
}

export const usePostGlobalVariables: useMutationFunctionType<
  undefined,
  PostGlobalVariablesParams
> = (options?) => {
  const { mutate, queryClient } = UseRequestProcessor();

  const postGlobalVariablesFunction = async ({
    name,
    value,
    type,
    default_fields = [],
    category,
  }: PostGlobalVariablesParams): Promise<PostGlobalVariablesResponse> => {
    const res = await api.post(`${getURL("VARIABLES")}/`, {
      name,
      value,
      type,
      default_fields: default_fields,
      category,
    });
    return res.data;
  };

  const mutation: UseMutationResult<any, any, PostGlobalVariablesParams> =
    mutate(["usePostGlobalVariables"], postGlobalVariablesFunction, {
      onSettled: () => {
        queryClient.refetchQueries({ queryKey: ["useGetGlobalVariables"] });
      },
      retry: false,
      ...options,
    });

  return mutation;
};
