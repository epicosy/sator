from graphene import Schema
from sator.core.graphql.query import Query
from sator.core.graphql.mutation import Mutation

schema = Schema(query=Query, mutation=Mutation)
