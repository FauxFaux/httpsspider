create table thyme_cidr (block cidr not null, net_id bigint not null);
create index on thyme_cidr using gist (block inet_ops);
create table lookups(name varchar not null, addr inet not null);

-- <data-used-autnums while read x y; do printf "%s\t%s\n" "$x" "$y"; done > autnums.tsv

\copy thyme_cidr from 'data-raw-table' CSV delimiter E'\t';
\copy thyme_names from 'autnums.tsv' csv delimiter E'\t' quote E'\x01';

select net, cnt, net_id, name from (select * from (select net, count(*) cnt from (select (addr & inet '255.255.0.0') net from (select distinct addr from lookups) q) a group by 1) b order by cnt desc limit 200) q left join thyme_cidr on (net && block) left join thyme_names using (net_id);

