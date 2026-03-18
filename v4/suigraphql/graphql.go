package suigraphql

import (
	"context"

	"github.com/Khan/genqlient/graphql"
)

func GetDynamicFields(
	ctx_ context.Context,
	client_ graphql.Client,
	parentId string,
) (data_ *getDynamicFieldsResponse, err_ error) {
	data, err := getDynamicFields(
		ctx_,
		client_,
		parentId,
	)

	return data, err
}

func GetDynamicFieldsAddressDynamicFieldsDynamicFieldConnectionNodesDynamicFieldValueMoveValue(g getDynamicFieldsAddressDynamicFieldsDynamicFieldConnectionNodesDynamicFieldValue) getDynamicFieldsAddressDynamicFieldsDynamicFieldConnectionNodesDynamicFieldValueMoveValue {
	k := g.(*getDynamicFieldsAddressDynamicFieldsDynamicFieldConnectionNodesDynamicFieldValueMoveValue)
	return *k
}
