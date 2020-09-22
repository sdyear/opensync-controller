/*
 * Table structure for table 'radcheck'
 */
CREATE TABLE IF NOT EXISTS radcheck (
	UserName		text NOT NULL DEFAULT '',
	Password		text NOT NULL DEFAULT ''
);
create index radcheck_UserName on radcheck (UserName,Attribute);
/*
 * Use this index if you use case insensitive queries
 */
-- create index radcheck_UserName_lower on radcheck (lower(UserName),Attribute);
