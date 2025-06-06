USE [master]
GO
/****** Object:  Database [HeatherDB]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE DATABASE [HeatherDB]
 CONTAINMENT = NONE
 ON  PRIMARY 
( NAME = N'HeatherDB', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\DATA\HeatherDB.mdf' , SIZE = 8192KB , MAXSIZE = UNLIMITED, FILEGROWTH = 65536KB )
 LOG ON 
( NAME = N'HeatherDB_log', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\DATA\HeatherDB_log.ldf' , SIZE = 8192KB , MAXSIZE = 2048GB , FILEGROWTH = 65536KB )
 WITH CATALOG_COLLATION = DATABASE_DEFAULT, LEDGER = OFF
GO
ALTER DATABASE [HeatherDB] SET COMPATIBILITY_LEVEL = 160
GO
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [HeatherDB].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [HeatherDB] SET ANSI_NULL_DEFAULT OFF 
GO
ALTER DATABASE [HeatherDB] SET ANSI_NULLS OFF 
GO
ALTER DATABASE [HeatherDB] SET ANSI_PADDING OFF 
GO
ALTER DATABASE [HeatherDB] SET ANSI_WARNINGS OFF 
GO
ALTER DATABASE [HeatherDB] SET ARITHABORT OFF 
GO
ALTER DATABASE [HeatherDB] SET AUTO_CLOSE OFF 
GO
ALTER DATABASE [HeatherDB] SET AUTO_SHRINK OFF 
GO
ALTER DATABASE [HeatherDB] SET AUTO_UPDATE_STATISTICS ON 
GO
ALTER DATABASE [HeatherDB] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO
ALTER DATABASE [HeatherDB] SET CURSOR_DEFAULT  GLOBAL 
GO
ALTER DATABASE [HeatherDB] SET CONCAT_NULL_YIELDS_NULL OFF 
GO
ALTER DATABASE [HeatherDB] SET NUMERIC_ROUNDABORT OFF 
GO
ALTER DATABASE [HeatherDB] SET QUOTED_IDENTIFIER OFF 
GO
ALTER DATABASE [HeatherDB] SET RECURSIVE_TRIGGERS OFF 
GO
ALTER DATABASE [HeatherDB] SET  DISABLE_BROKER 
GO
ALTER DATABASE [HeatherDB] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO
ALTER DATABASE [HeatherDB] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO
ALTER DATABASE [HeatherDB] SET TRUSTWORTHY OFF 
GO
ALTER DATABASE [HeatherDB] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO
ALTER DATABASE [HeatherDB] SET PARAMETERIZATION SIMPLE 
GO
ALTER DATABASE [HeatherDB] SET READ_COMMITTED_SNAPSHOT OFF 
GO
ALTER DATABASE [HeatherDB] SET HONOR_BROKER_PRIORITY OFF 
GO
ALTER DATABASE [HeatherDB] SET RECOVERY FULL 
GO
ALTER DATABASE [HeatherDB] SET  MULTI_USER 
GO
ALTER DATABASE [HeatherDB] SET PAGE_VERIFY CHECKSUM  
GO
ALTER DATABASE [HeatherDB] SET DB_CHAINING OFF 
GO
ALTER DATABASE [HeatherDB] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO
ALTER DATABASE [HeatherDB] SET TARGET_RECOVERY_TIME = 60 SECONDS 
GO
ALTER DATABASE [HeatherDB] SET DELAYED_DURABILITY = DISABLED 
GO
ALTER DATABASE [HeatherDB] SET ACCELERATED_DATABASE_RECOVERY = OFF  
GO
EXEC sys.sp_db_vardecimal_storage_format N'HeatherDB', N'ON'
GO
ALTER DATABASE [HeatherDB] SET QUERY_STORE = ON
GO
ALTER DATABASE [HeatherDB] SET QUERY_STORE (OPERATION_MODE = READ_WRITE, CLEANUP_POLICY = (STALE_QUERY_THRESHOLD_DAYS = 30), DATA_FLUSH_INTERVAL_SECONDS = 900, INTERVAL_LENGTH_MINUTES = 60, MAX_STORAGE_SIZE_MB = 1000, QUERY_CAPTURE_MODE = AUTO, SIZE_BASED_CLEANUP_MODE = AUTO, MAX_PLANS_PER_QUERY = 200, WAIT_STATS_CAPTURE_MODE = ON)
GO
USE [HeatherDB]
GO
/****** Object:  User [owner_user]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE USER [owner_user] FOR LOGIN [owner_user] WITH DEFAULT_SCHEMA=[dbo]
GO
/****** Object:  User [devops_user]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE USER [devops_user] FOR LOGIN [devops_user] WITH DEFAULT_SCHEMA=[dbo]
GO
/****** Object:  User [dev_user]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE USER [dev_user] FOR LOGIN [dev_user] WITH DEFAULT_SCHEMA=[dbo]
GO
/****** Object:  User [analyst_user]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE USER [analyst_user] FOR LOGIN [analyst_user] WITH DEFAULT_SCHEMA=[dbo]
GO
/****** Object:  User [admin_user]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE USER [admin_user] FOR LOGIN [admin_user] WITH DEFAULT_SCHEMA=[dbo]
GO
/****** Object:  DatabaseRole [tenant_role]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE ROLE [tenant_role]
GO
/****** Object:  DatabaseRole [owner_role]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE ROLE [owner_role]
GO
/****** Object:  DatabaseRole [devops_role]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE ROLE [devops_role]
GO
/****** Object:  DatabaseRole [developer_role]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE ROLE [developer_role]
GO
/****** Object:  DatabaseRole [analyst_role]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE ROLE [analyst_role]
GO
/****** Object:  DatabaseRole [admin_role]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE ROLE [admin_role]
GO
ALTER ROLE [owner_role] ADD MEMBER [owner_user]
GO
ALTER ROLE [devops_role] ADD MEMBER [devops_user]
GO
ALTER ROLE [developer_role] ADD MEMBER [dev_user]
GO
ALTER ROLE [analyst_role] ADD MEMBER [analyst_user]
GO
ALTER ROLE [db_owner] ADD MEMBER [admin_user]
GO
/****** Object:  Schema [heather]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE SCHEMA [heather]
GO
/****** Object:  UserDefinedFunction [heather].[enum2str$admins$USER_TYPE]    Script Date: 19/05/2025 8:18:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [heather].[enum2str$admins$USER_TYPE] 
( 
   @setval tinyint
)
RETURNS nvarchar(max)
AS 
   BEGIN
      RETURN 
         CASE @setval
            WHEN 1 THEN 'Admin'
            ELSE ''
         END
   END
GO
/****** Object:  UserDefinedFunction [heather].[enum2str$users$USER_TYPE]    Script Date: 19/05/2025 8:18:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [heather].[enum2str$users$USER_TYPE] 
( 
   @setval tinyint
)
RETURNS nvarchar(max)
AS 
   BEGIN
      RETURN 
         CASE @setval
            WHEN 1 THEN 'Tenant'
            WHEN 2 THEN 'Advertiser'
            ELSE ''
         END
   END
GO
/****** Object:  UserDefinedFunction [heather].[norm_enum$admins$USER_TYPE]    Script Date: 19/05/2025 8:18:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [heather].[norm_enum$admins$USER_TYPE] 
( 
   @setval nvarchar(max)
)
RETURNS nvarchar(max)
AS 
   BEGIN
      RETURN heather.enum2str$admins$USER_TYPE(heather.str2enum$admins$USER_TYPE(@setval))
   END
GO
/****** Object:  UserDefinedFunction [heather].[norm_enum$users$USER_TYPE]    Script Date: 19/05/2025 8:18:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [heather].[norm_enum$users$USER_TYPE] 
( 
   @setval nvarchar(max)
)
RETURNS nvarchar(max)
AS 
   BEGIN
      RETURN heather.enum2str$users$USER_TYPE(heather.str2enum$users$USER_TYPE(@setval))
   END
GO
/****** Object:  UserDefinedFunction [heather].[str2enum$admins$USER_TYPE]    Script Date: 19/05/2025 8:18:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [heather].[str2enum$admins$USER_TYPE] 
( 
   @setval nvarchar(max)
)
RETURNS tinyint
AS 
   BEGIN
      RETURN 
         CASE @setval
            WHEN 'Admin' THEN 1
            ELSE 0
         END
   END
GO
/****** Object:  UserDefinedFunction [heather].[str2enum$users$USER_TYPE]    Script Date: 19/05/2025 8:18:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [heather].[str2enum$users$USER_TYPE] 
( 
   @setval nvarchar(max)
)
RETURNS tinyint
AS 
   BEGIN
      RETURN 
         CASE @setval
            WHEN 'Tenant' THEN 1
            WHEN 'Advertiser' THEN 2
            ELSE 0
         END
   END
GO
/****** Object:  Table [heather].[admins]    Script Date: 19/05/2025 8:18:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [heather].[admins](
	[ADMIN_ID] [int] IDENTITY(4,1) NOT NULL,
	[ADMIN_EMAIL] [nvarchar](50) NOT NULL,
	[ADMIN_PASS] [nvarchar](20) NOT NULL,
	[ADMIN_FNAME] [nvarchar](50) NOT NULL,
	[ADMIN_LNAME] [nvarchar](50) NOT NULL,
	[ADMIN_CONTACT] [bigint] NOT NULL,
	[USER_TYPE] [nvarchar](5) NOT NULL,
 CONSTRAINT [PK_admins_ADMIN_ID] PRIMARY KEY CLUSTERED 
(
	[ADMIN_ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [heather].[property]    Script Date: 19/05/2025 8:18:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [heather].[property](
	[PROP_ID] [int] IDENTITY(17,1) NOT NULL,
	[PROP_NAME] [nvarchar](75) NULL,
	[ADVERTISER_ID] [int] NOT NULL,
	[PROP_ADDRESS] [nvarchar](100) NULL,
	[POSTCODE] [int] NULL,
	[FLOOR_AREA] [decimal](10, 2) NULL,
	[ROOM_NUM] [int] NOT NULL,
	[PROP_DESCRIPTION] [nvarchar](100) NULL,
	[PROP_PRICE] [decimal](10, 2) NULL,
	[PROP_RULES] [nvarchar](100) NULL,
	[image] [nvarchar](100) NULL,
	[status] [nvarchar](20) NOT NULL,
 CONSTRAINT [PK_property_PROP_ID] PRIMARY KEY CLUSTERED 
(
	[PROP_ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [heather].[room]    Script Date: 19/05/2025 8:18:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [heather].[room](
	[ROOM_ID] [int] IDENTITY(7,1) NOT NULL,
	[PROP_ID] [int] NOT NULL,
	[ROOM_IMAGE] [nvarchar](100) NOT NULL,
	[status] [nvarchar](20) NOT NULL,
 CONSTRAINT [PK_room_ROOM_ID] PRIMARY KEY CLUSTERED 
(
	[ROOM_ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [heather].[users]    Script Date: 19/05/2025 8:18:37 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [heather].[users](
	[USER_ID] [int] IDENTITY(43,1) NOT NULL,
	[USER_EMAIL] [nvarchar](50) NOT NULL,
	[USER_FNAME] [nvarchar](50) NULL,
	[USER_LNAME] [nvarchar](50) NULL,
	[USER_CONTACT] [bigint] NOT NULL,
	[USER_TYPE] [nvarchar](10) NOT NULL,
	[USER_PASS_HASH] [nvarchar](255) NULL,
 CONSTRAINT [PK_users_USER_ID] PRIMARY KEY CLUSTERED 
(
	[USER_ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY],
 CONSTRAINT [users$USER_CONTACT] UNIQUE NONCLUSTERED 
(
	[USER_CONTACT] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY],
 CONSTRAINT [users$USER_EMAIL] UNIQUE NONCLUSTERED 
(
	[USER_EMAIL] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Index [ADMIN_CONTACT]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE NONCLUSTERED INDEX [ADMIN_CONTACT] ON [heather].[admins]
(
	[ADMIN_CONTACT] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
GO
SET ANSI_PADDING ON
GO
/****** Object:  Index [ADMIN_EMAIL]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE NONCLUSTERED INDEX [ADMIN_EMAIL] ON [heather].[admins]
(
	[ADMIN_EMAIL] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
GO
/****** Object:  Index [fk_advertiser]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE NONCLUSTERED INDEX [fk_advertiser] ON [heather].[property]
(
	[ADVERTISER_ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
GO
/****** Object:  Index [fk_prop]    Script Date: 19/05/2025 8:18:37 PM ******/
CREATE NONCLUSTERED INDEX [fk_prop] ON [heather].[room]
(
	[PROP_ID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, SORT_IN_TEMPDB = OFF, DROP_EXISTING = OFF, ONLINE = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
GO
ALTER TABLE [heather].[property] ADD  DEFAULT (NULL) FOR [PROP_NAME]
GO
ALTER TABLE [heather].[property] ADD  DEFAULT (NULL) FOR [PROP_ADDRESS]
GO
ALTER TABLE [heather].[property] ADD  DEFAULT (NULL) FOR [POSTCODE]
GO
ALTER TABLE [heather].[property] ADD  DEFAULT (NULL) FOR [FLOOR_AREA]
GO
ALTER TABLE [heather].[property] ADD  DEFAULT (NULL) FOR [PROP_DESCRIPTION]
GO
ALTER TABLE [heather].[property] ADD  DEFAULT (NULL) FOR [PROP_PRICE]
GO
ALTER TABLE [heather].[property] ADD  DEFAULT (NULL) FOR [PROP_RULES]
GO
ALTER TABLE [heather].[property] ADD  DEFAULT (NULL) FOR [image]
GO
ALTER TABLE [heather].[property] ADD  DEFAULT (N'pending') FOR [status]
GO
ALTER TABLE [heather].[room] ADD  DEFAULT (N'pending') FOR [status]
GO
ALTER TABLE [heather].[users] ADD  DEFAULT (NULL) FOR [USER_FNAME]
GO
ALTER TABLE [heather].[users] ADD  DEFAULT (NULL) FOR [USER_LNAME]
GO
ALTER TABLE [heather].[property]  WITH NOCHECK ADD  CONSTRAINT [property$fk_advertiser] FOREIGN KEY([ADVERTISER_ID])
REFERENCES [heather].[users] ([USER_ID])
ON UPDATE CASCADE
ON DELETE CASCADE
GO
ALTER TABLE [heather].[property] CHECK CONSTRAINT [property$fk_advertiser]
GO
ALTER TABLE [heather].[property]  WITH NOCHECK ADD  CONSTRAINT [property$fk_owner] FOREIGN KEY([ADVERTISER_ID])
REFERENCES [heather].[users] ([USER_ID])
GO
ALTER TABLE [heather].[property] CHECK CONSTRAINT [property$fk_owner]
GO
ALTER TABLE [heather].[room]  WITH NOCHECK ADD  CONSTRAINT [room$fk_prop] FOREIGN KEY([PROP_ID])
REFERENCES [heather].[property] ([PROP_ID])
ON UPDATE CASCADE
ON DELETE CASCADE
GO
ALTER TABLE [heather].[room] CHECK CONSTRAINT [room$fk_prop]
GO
EXEC sys.sp_addextendedproperty @name=N'MS_SSMA_SOURCE', @value=N'heather.admins' , @level0type=N'SCHEMA',@level0name=N'heather', @level1type=N'FUNCTION',@level1name=N'enum2str$admins$USER_TYPE'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_SSMA_SOURCE', @value=N'heather.users' , @level0type=N'SCHEMA',@level0name=N'heather', @level1type=N'FUNCTION',@level1name=N'enum2str$users$USER_TYPE'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_SSMA_SOURCE', @value=N'heather.admins' , @level0type=N'SCHEMA',@level0name=N'heather', @level1type=N'FUNCTION',@level1name=N'norm_enum$admins$USER_TYPE'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_SSMA_SOURCE', @value=N'heather.users' , @level0type=N'SCHEMA',@level0name=N'heather', @level1type=N'FUNCTION',@level1name=N'norm_enum$users$USER_TYPE'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_SSMA_SOURCE', @value=N'heather.admins' , @level0type=N'SCHEMA',@level0name=N'heather', @level1type=N'FUNCTION',@level1name=N'str2enum$admins$USER_TYPE'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_SSMA_SOURCE', @value=N'heather.users' , @level0type=N'SCHEMA',@level0name=N'heather', @level1type=N'FUNCTION',@level1name=N'str2enum$users$USER_TYPE'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_SSMA_SOURCE', @value=N'heather.admins' , @level0type=N'SCHEMA',@level0name=N'heather', @level1type=N'TABLE',@level1name=N'admins'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_SSMA_SOURCE', @value=N'heather.property' , @level0type=N'SCHEMA',@level0name=N'heather', @level1type=N'TABLE',@level1name=N'property'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_SSMA_SOURCE', @value=N'heather.room' , @level0type=N'SCHEMA',@level0name=N'heather', @level1type=N'TABLE',@level1name=N'room'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_SSMA_SOURCE', @value=N'heather.users' , @level0type=N'SCHEMA',@level0name=N'heather', @level1type=N'TABLE',@level1name=N'users'
GO
USE [master]
GO
ALTER DATABASE [HeatherDB] SET  READ_WRITE 
GO
