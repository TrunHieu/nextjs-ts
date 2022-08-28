import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateBookmarkDto, EditBookmarkDto } from './dto';

@Injectable()
export class BookmarkService {
  constructor(private prismaService: PrismaService) {}

  getBookmark() {
    return this.prismaService.bookmark.findMany();
  }

  getBookmarkByUserId(userId: number) {
    return this.prismaService.bookmark.findMany({
      where: {
        userId,
      },
    });
  }

  getBookmarkById(userId: number, bookmarkId: number) {
    return this.prismaService.bookmark.findFirst({
      where: {
        id: bookmarkId,
        userId,
      },
    });
  }

  async createBookmark(userId: number, createBookmarkDto: CreateBookmarkDto) {
    return this.prismaService.bookmark.create({
      data: {
        userId,
        ...createBookmarkDto,
      },
    });
  }

  async editBookmarkById(
    userId: number,
    bookmarkId: number,
    editBookmarkDto: EditBookmarkDto,
  ) {
    return Promise.resolve();
  }

  async deleteBookmarkById(userId: number, bookmarkId: number) {
    const bookmark = await this.prismaService.bookmark.findUnique({
      where: {
        id: bookmarkId,
      },
    });

    if (!bookmark && bookmark.userId !== userId) {
      throw new ForbiddenException('Access to resources denied');
    }

    await this.prismaService.bookmark.delete({
      where: {
        id: bookmarkId,
      },
    });
  }
}
