from typing import List
from sqlalchemy.sql import func

from sqlalchemy.orm import aliased

import graphene
import sqlalchemy
from sqlalchemy.sql import select

from graphene import ObjectType
from graphql import GraphQLError
# from graphql_relay import to_global_id
from sator.core.graphql.objects import GrapheneCount, ProfileObject

from sator.core.graphql.objects import CWE, Vulnerability, VulnerabilityModel, VulnerabilityCWE, CommitFileModel, \
    VulnerabilityCWEModel, Reference, Commit, Repository, CommitModel, ConfigurationModel, RepositoryModel, \
    ProductModel, ProductTypeModel, DatasetVulnerability, DatasetVulnerabilityModel, Line, LineModel, Function,\
    FunctionModel, ReferenceTagModel, ReferenceModel, CommitFile

from sator.core.graphql.queries.pagination import PaginationQuery
from sator.core.graphql.queries.objects import ObjectsQuery
from sator.core.graphql.queries.counts import CountsQuery


class Link(ObjectType):
    at = graphene.String()
    to = graphene.String()
    count = graphene.Int()


class Stats(ObjectType):
    total = graphene.Int()
    labeled = graphene.Int()
    references = graphene.Int()
    commits = graphene.Int()


class VulnerabilityNode(ObjectType):
    node = graphene.Field(Vulnerability)
    cursor = graphene.String()


class Position(ObjectType):
    line = graphene.Int()
    column = graphene.Int()


class MethodBoundary(ObjectType):
    name = graphene.String()
    start = graphene.Field(lambda: Position)
    end = graphene.Field(lambda: Position)
    code = graphene.List(graphene.String)


class ProfileCount(ObjectType):
    total = graphene.Int()
    year = graphene.List(lambda: GrapheneCount)
    cwe = graphene.List(lambda: GrapheneCount)
    score = graphene.List(lambda: GrapheneCount)
    changes = graphene.List(lambda: GrapheneCount)
    files = graphene.List(lambda: GrapheneCount)
    extensions = graphene.List(lambda: GrapheneCount)


def check_profile_vuln_fields(start_year, end_year, start_score, end_score):
    # min score should not be negative and max score should not be greater than 100
    if start_score and start_score < 0:
        raise GraphQLError("Invalid min score")

    if end_score and end_score > 10:
        raise GraphQLError("Invalid max score")

    if start_year and start_year < 1987:
        raise GraphQLError("Invalid start year")

    if end_year:
        from datetime import datetime

        # should not be greater than the current year by 1, get year with Date
        if end_year > datetime.now().year + 1:
            raise GraphQLError("Invalid end year")

    if start_year and end_year and start_year > end_year:
        raise GraphQLError("Invalid date range")

    if start_score and end_score and start_score > end_score:
        raise GraphQLError("Invalid score range")


def check_profile_commit_fields(min_changes, max_changes, min_files, max_files):
    if min_changes and min_changes < 0:
        raise GraphQLError("Invalid min changes")

    if min_files and min_files < 0:
        raise GraphQLError("Invalid min files")

    if min_changes and max_changes and min_changes > max_changes:
        raise GraphQLError("Invalid files range")

    if min_files and max_files and min_files > max_files:
        raise GraphQLError("Invalid changes range")


def profiling_vuln_query(info, start_year, end_year, cwe_ids, start_score, end_score, has_exploit, has_advisory):
    check_profile_vuln_fields(start_year, end_year, start_score, end_score)

    query = Vulnerability.get_query(info).outerjoin(VulnerabilityCWEModel,
                                                    VulnerabilityModel.id == VulnerabilityCWEModel.vulnerability_id)

    if cwe_ids:
        query = query.filter(VulnerabilityCWEModel.cwe_id.in_(cwe_ids))

    if start_year:
        query = query.filter(VulnerabilityModel.published_date >= f'{start_year}-01-01')

    if end_year:
        query = query.filter(VulnerabilityModel.published_date <= f'{end_year}-12-31')

    if start_score:
        query = query.filter(VulnerabilityModel.exploitability >= start_score)

    if end_score:
        query = query.filter(VulnerabilityModel.exploitability <= end_score)

    if has_exploit:
        # get the ReferenceTag id for the exploit tag
        subquery = Reference.get_query(info).join(ReferenceTagModel).filter(ReferenceTagModel.tag_id == 10). \
            distinct().filter(ReferenceModel.vulnerability_id == VulnerabilityModel.id).exists()

        query = query.filter(subquery)

    if has_advisory:
        # get the ReferenceTag id for the advisory tag (1 and 16)
        subquery = Reference.get_query(info).join(ReferenceTagModel).filter(ReferenceTagModel.tag_id.in_([1, 16])). \
            distinct().filter(ReferenceModel.vulnerability_id == VulnerabilityModel.id).exists()

        query = query.filter(subquery)

    return query


def profiling_commit_query(info, query, min_changes, max_changes, min_files, max_files, extensions):
    check_profile_commit_fields(min_changes, max_changes, min_files, max_files)

    vuln_query = query.with_entities(VulnerabilityModel.id).subquery()
    commit_query = (Commit.get_query(info).filter(CommitModel.vulnerability_id.in_(select([vuln_query])))
                    .filter(CommitModel.kind != 'parent'))

    commit_query = commit_query.filter(CommitModel.changes.isnot(None))
    commit_query = commit_query.filter(CommitModel.files_count.isnot(None))

    if min_changes or max_changes or min_files or max_files:
        commit_query = commit_query.group_by(CommitModel.id, CommitModel.vulnerability_id)

        if min_changes or max_changes:
            if min_changes:
                commit_query = commit_query.having(sqlalchemy.func.min(CommitModel.changes) >= min_changes)

            if max_changes:
                commit_query = commit_query.having(sqlalchemy.func.max(CommitModel.changes) <= max_changes)

        if min_files or max_files:
            if min_files:
                commit_query = commit_query.having(sqlalchemy.func.min(CommitModel.files_count) >= min_files)

            if max_files:
                commit_query = commit_query.having(sqlalchemy.func.max(CommitModel.files_count) <= max_files)

        subquery = commit_query.subquery()
        commit_query = (Commit.get_query(info).join(subquery, CommitModel.id == subquery.c.id)
                        .filter(subquery.c.vulnerability_id == CommitModel.vulnerability_id))

    if extensions:
        extension_subquery = (CommitFile.get_query(info)
                              .filter(CommitFileModel.commit_id == CommitModel.id)
                              .filter(CommitFileModel.extension.in_(extensions))
                              .subquery())

        commit_query = commit_query.join(extension_subquery, extension_subquery.c.commit_id == CommitModel.id)

    return commit_query


class Query(CountsQuery, ObjectsQuery, PaginationQuery, ObjectType):
    stats = graphene.Field(Stats)
    links = graphene.List(Link)

    language_extension_links_count = graphene.List(lambda: Link, filter_counts=graphene.Int())
    lang_product_links_count = graphene.List(lambda: Link, filter_counts=graphene.Int())

    search_vulnerability = graphene.List(lambda: Vulnerability, keyword=graphene.String(), limit=graphene.Int())
    datasets_overlap = graphene.Float(src_id=graphene.Int(), tgt_id=graphene.Int())
    functions = graphene.List(lambda: MethodBoundary, file_id=graphene.String())
    profile_count = graphene.Field(ProfileCount, start_year=graphene.Int(), end_year=graphene.Int(),
                                   cwe_ids=graphene.List(graphene.Int), start_score=graphene.Float(),
                                   end_score=graphene.Float(), has_code=graphene.Boolean(), has_exploit=graphene.Boolean(),
                                   has_advisory=graphene.Boolean(), min_changes=graphene.Int(),
                                   max_changes=graphene.Int(), min_files=graphene.Int(), max_files=graphene.Int(),
                                   extensions=graphene.List(graphene.String))
    profiles = graphene.List(lambda: ProfileObject)

    def resolve_profiles(self, info):
        return ProfileObject.get_query(info).all()

    def resolve_profile_count(self, info, start_year: int = None, end_year: int = None, cwe_ids: List[int] = None,
                              start_score: float = None, end_score: float = None, has_code: bool = False,
                              has_exploit: bool = False, has_advisory: bool = False, min_changes: int = None,
                              max_changes: int = None, min_files: int = None, max_files: int = None,
                              extensions: List[str] = None):

        changes_count = []
        files_count = []
        extensions_count = []

        print("has_code", has_code, "min_changes", min_changes, "max_changes", max_changes)

        query = profiling_vuln_query(info, start_year, end_year, cwe_ids, start_score, end_score, has_exploit,
                                     has_advisory)

        if has_code:
            commit_query = profiling_commit_query(info, query, min_changes, max_changes, min_files, max_files,
                                                  extensions)

            vuln_query = commit_query.with_entities(CommitModel.vulnerability_id).subquery()
            query = query.filter(VulnerabilityModel.id.in_(select([vuln_query])))

            changes_count = (commit_query.group_by(CommitModel.changes)
                             .with_entities(CommitModel.changes, func.count().label('count'))
                             .all())

            files_count = (commit_query.group_by(CommitModel.files_count)
                           .with_entities(CommitModel.files_count, func.count().label('count'))
                           .all())

            commit_subquery = commit_query.with_entities(CommitModel.id).subquery()
            extensions_count = (
                CommitFile.get_query(info).filter(CommitFileModel.commit_id.in_(select([commit_subquery])))
                .group_by(CommitFileModel.extension)
                .with_entities(CommitFileModel.extension, func.count().label('count'))
                .all())

        year_counts = query.group_by(
            func.extract('year', VulnerabilityModel.published_date)
        ).with_entities(
            func.extract('year', VulnerabilityModel.published_date).label('year'),
            func.count().label('count')
        ).all()

        cwe_counts = query.group_by(
            VulnerabilityCWEModel.cwe_id
        ).with_entities(
            VulnerabilityCWEModel.cwe_id,
            func.count().label('count')
        ).all()

        score_counts = query.group_by(
            VulnerabilityModel.exploitability
        ).with_entities(
            VulnerabilityModel.exploitability.label('score'),
            func.count().label('count')
        ).all()

        return ProfileCount(year=[GrapheneCount(key=year, value=count) for year, count in year_counts],
                            cwe=[GrapheneCount(key=cwe_id, value=count) for cwe_id, count in cwe_counts],
                            score=[GrapheneCount(key=score, value=count) for score, count in score_counts],
                            changes=[GrapheneCount(key=changes, value=count) for changes, count in changes_count],
                            files=[GrapheneCount(key=files, value=count) for files, count in files_count],
                            extensions=[GrapheneCount(key=extension, value=count) for extension, count in extensions_count],
                            total=query.count())

    def resolve_functions(self, info, file_id: str):
        return Function.get_query(info).filter_by(commit_file_id=file_id).order_by(FunctionModel.start).all()

    def resolve_datasets_overlap(self, info, src_id: int, tgt_id: int):
        src_dataset_vulns = DatasetVulnerability.get_query(info).filter(DatasetVulnerabilityModel.dataset_id == src_id).all()
        tgt_dataset_vulns = DatasetVulnerability.get_query(info).filter(DatasetVulnerabilityModel.dataset_id == tgt_id).all()
        src_dataset_vulns_ids = [x.vulnerability_id for x in src_dataset_vulns]
        tgt_dataset_vulns_ids = [x.vulnerability_id for x in tgt_dataset_vulns]
        overlap = set(src_dataset_vulns_ids).intersection(set(tgt_dataset_vulns_ids))

        if len(overlap) == 0:
            return 0

        if len(src_dataset_vulns_ids) == 0:
            return 0

        return len(overlap)/len(src_dataset_vulns_ids)*100

    def resolve_search_vulnerability(self, info, keyword: str, limit: int = 10):
        return Vulnerability.get_query(info).filter(VulnerabilityModel.id.ilike(f'%{keyword}%'))\
            .limit(limit).all()

    def resolve_language_extension_links_count(self, info, filter_counts: int = None):
        query = Repository.get_query(info).join(CommitModel).join(CommitFileModel)\
            .group_by(RepositoryModel.language, CommitFileModel.extension)\
            .with_entities(RepositoryModel.language, CommitFileModel.extension, sqlalchemy.func.count()).all()

        if filter_counts:
            return [Link(at=at, to=to, count=count) for at, to, count in query if count >= filter_counts]

        return [Link(at=at, to=to, count=count) for at, to, count in query]

    def resolve_lang_product_links_count(self, info, filter_counts: int = None):
        query = Repository.get_query(info).join(CommitModel).join(VulnerabilityModel).join(ConfigurationModel)\
            .join(ProductModel).join(ProductTypeModel).filter(RepositoryModel.language != None)\
            .group_by(RepositoryModel.language, ProductTypeModel.name)\
            .with_entities(RepositoryModel.language, ProductTypeModel.name, sqlalchemy.func.count()).all()

        if filter_counts:
            return [Link(at=at, to=to, count=count) for at, to, count in query if count > filter_counts]

        return [Link(at=at, to=to, count=count) for at, to, count in query]

    def resolve_links(self, info):
        cwe_ids = CWE.get_query(info).all()
        mapping = {}

        for cwe in cwe_ids:
            cwe_counts = VulnerabilityCWE.get_query(info).filter(VulnerabilityCWEModel.cwe_id == cwe.id).count()

            if cwe_counts < 1:
                continue

            bf_classes = CWE.resolve_bf_class(cwe, info)
            phases = CWE.resolve_phases(cwe, info)
            operations = CWE.resolve_operations(cwe, info)

            if len(bf_classes) > 1:
                continue

            if bf_classes[0].name == "None":
                continue

            if len(phases) > 1:
                continue

            link_name = f"{bf_classes[0].name}_{phases[0].name}"

            if link_name not in mapping:
                mapping[link_name] = Link(bf_classes[0].name, phases[0].name, cwe_counts)
            else:
                mapping[link_name].count += cwe_counts

            if len(operations) > 1:
                continue

            link_name = f"{phases[0].name}_{operations[0].name}"

            if link_name not in mapping:
                mapping[link_name] = Link(phases[0].name, operations[0].name, cwe_counts)
            else:
                mapping[link_name].count += cwe_counts

        return list(mapping.values())

    def resolve_stats(self, info):
        total = Vulnerability.get_query(info).count()
        references = Reference.get_query(info).count()
        labeled = VulnerabilityCWE.get_query(info).count()
        commits = Commit.get_query(info).count()

        return Stats(total, labeled, references, commits)
