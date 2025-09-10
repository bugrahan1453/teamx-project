// apps/api/src/tasks/tasks.module.ts
import { Module } from '@nestjs/common';
import { TasksService } from './tasks.service';
import { TasksController } from './tasks.controller';

@Module({
  providers: [TasksService],
  controllers: [TasksController],
  exports: [TasksService],
})
export class TasksModule {}

// apps/api/src/tasks/tasks.service.ts
import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';

@Injectable()
export class TasksService {
  constructor(private prisma: PrismaService) {}

  async create(createTaskDto: CreateTaskDto, user: any) {
    const task = await this.prisma.task.create({
      data: {
        ...createTaskDto,
        tenantId: user.tenantId,
        assignedById: user.userId,
      },
      include: {
        assignedBy: { select: { id: true, name: true, avatarUrl: true } },
        assignedTo: { select: { id: true, name: true, avatarUrl: true } },
        attachments: true,
        _count: { select: { comments: true } }
      }
    });

    return { ...task, commentsCount: task._count.comments };
  }

  async findAll(tenantId: string, user: any) {
    const where: any = { tenantId };

    // RBAC: Limit visibility based on role
    if (!['OWNER', 'MANAGER'].includes(user.role)) {
      where.OR = [
        { assignedToId: user.userId },
        { assignedById: user.userId }
      ];
    }

    const tasks = await this.prisma.task.findMany({
      where,
      include: {
        assignedBy: { select: { id: true, name: true, avatarUrl: true } },
        assignedTo: { select: { id: true, name: true, avatarUrl: true } },
        attachments: true,
        _count: { select: { comments: true } }
      },
      orderBy: [
        { priority: 'desc' },
        { createdAt: 'desc' }
      ],
      take: 50,
    });

    return {
      data: tasks.map(task => ({
        ...task,
        commentsCount: task._count.comments
      })),
      total: tasks.length
    };
  }

  async findOne(id: string, user: any) {
    const task = await this.prisma.task.findFirst({
      where: { id, tenantId: user.tenantId },
      include: {
        assignedBy: { select: { id: true, name: true, avatarUrl: true } },
        assignedTo: { select: { id: true, name: true, avatarUrl: true } },
        attachments: true,
        comments: {
          include: { author: { select: { id: true, name: true, avatarUrl: true } } },
          orderBy: { createdAt: 'asc' }
        }
      }
    });

    if (!task) {
      throw new NotFoundException('Görev bulunamadı');
    }

    return task;
  }

  async update(id: string, updateTaskDto: UpdateTaskDto, user: any) {
    const task = await this.findOne(id, user);
    
    return this.prisma.task.update({
      where: { id },
      data: updateTaskDto,
      include: {
        assignedBy: { select: { id: true, name: true, avatarUrl: true } },
        assignedTo: { select: { id: true, name: true, avatarUrl: true } },
      }
    });
  }

  async approve(id: string, user: any) {
    const task = await this.findOne(id, user);

    if (task.status !== 'DONE') {
      throw new ForbiddenException('Sadece tamamlanan görevler onaylanabilir');
    }

    return this.prisma.task.update({
      where: { id },
      data: {
        status: 'APPROVED',
        approvedById: user.userId,
        approvedAt: new Date(),
      }
    });
  }

  async getStats(tenantId: string, user: any) {
    const where: any = { tenantId };

    if (!['OWNER', 'MANAGER'].includes(user.role)) {
      where.OR = [
        { assignedToId: user.userId },
        { assignedById: user.userId }
      ];
    }

    const [total, completed, pending, inProgress] = await Promise.all([
      this.prisma.task.count({ where }),
      this.prisma.task.count({ where: { ...where, status: 'APPROVED' } }),
      this.prisma.task.count({ where: { ...where, status: 'OPEN' } }),
      this.prisma.task.count({ where: { ...where, status: 'IN_PROGRESS' } }),
    ]);

    const productivity = total > 0 ? Math.round((completed / total) * 100) : 0;

    return {
      total,
      completed,
      pending,
      inProgress,
      productivity,
      pendingApproval: await this.prisma.task.count({ where: { ...where, status: 'DONE' } })
    };
  }
}

// apps/api/src/tasks/tasks.controller.ts
import { Controller, Get, Post, Body, Patch, Param, UseGuards, Request } from '@nestjs/common';
import { TasksService } from './tasks.service';
import { CreateTaskDto } from './dto/create-task.dto';
import { UpdateTaskDto } from './dto/update-task.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@Controller('tasks')
@UseGuards(JwtAuthGuard)
export class TasksController {
  constructor(private readonly tasksService: TasksService) {}

  @Post()
  create(@Body() createTaskDto: CreateTaskDto, @Request() req) {
    return this.tasksService.create(createTaskDto, req.user);
  }

  @Get()
  findAll(@Request() req) {
    return this.tasksService.findAll(req.user.tenantId, req.user);
  }

  @Get('stats')
  getStats(@Request() req) {
    return this.tasksService.getStats(req.user.tenantId, req.user);
  }

  @Get(':id')
  findOne(@Param('id') id: string, @Request() req) {
    return this.tasksService.findOne(id, req.user);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateTaskDto: UpdateTaskDto, @Request() req) {
    return this.tasksService.update(id, updateTaskDto, req.user);
  }

  @Post(':id/approve')
  approve(@Param('id') id: string, @Request() req) {
    return this.tasksService.approve(id, req.user);
  }
}

// apps/api/src/tasks/dto/create-task.dto.ts
import { IsString, IsOptional, IsEnum, IsUUID, IsDateString, IsInt, IsArray } from 'class-validator';

export class CreateTaskDto {
  @IsString()
  title: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsString()
  @IsOptional()
  priority?: string = 'MEDIUM';

  @IsUUID()
  assignedToId: string;

  @IsDateString()
  @IsOptional()
  dueAt?: string;

  @IsInt()
  @IsOptional()
  estimatedHours?: number;

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  tags?: string[];
}

// apps/api/src/tasks/dto/update-task.dto.ts
import { IsOptional, IsString } from 'class-validator';

export class UpdateTaskDto {
  @IsOptional()
  @IsString()
  title?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsString()
  status?: string;

  @IsOptional()
  @IsString()
  priority?: string;
}

// apps/api/src/reports/reports.module.ts
import { Module } from '@nestjs/common';
import { ReportsService } from './reports.service';
import { ReportsController } from './reports.controller';

@Module({
  providers: [ReportsService],
  controllers: [ReportsController],
  exports: [ReportsService],
})
export class ReportsModule {}

// apps/api/src/reports/reports.service.ts
import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateReportDto } from './dto/create-report.dto';

@Injectable()
export class ReportsService {
  constructor(private prisma: PrismaService) {}

  async create(createReportDto: CreateReportDto, user: any) {
    return this.prisma.report.create({
      data: {
        ...createReportDto,
        tenantId: user.tenantId,
        createdById: user.userId,
      },
      include: {
        createdBy: { select: { id: true, name: true, avatarUrl: true } },
        attachments: true
      }
    });
  }

  async getTodayReports(tenantId: string, user: any) {
    const startOfDay = new Date();
    startOfDay.setHours(0, 0, 0, 0);
    const endOfDay = new Date();
    endOfDay.setHours(23, 59, 59, 999);

    const where: any = {
      tenantId,
      createdAt: { gte: startOfDay, lte: endOfDay },
      archivedAt: null
    };

    if (!['OWNER', 'MANAGER'].includes(user.role)) {
      where.createdById = user.userId;
    }

    const reports = await this.prisma.report.findMany({
      where,
      include: {
        createdBy: { select: { id: true, name: true, avatarUrl: true } },
        attachments: true
      },
      orderBy: { createdAt: 'desc' }
    });

    return { data: reports, total: reports.length };
  }

  async findAll(tenantId: string, type: string = 'today', user: any) {
    if (type === 'today') {
      return this.getTodayReports(tenantId, user);
    }

    const where: any = { tenantId };
    
    if (type === 'archived') {
      where.archivedAt = { not: null };
    }

    if (!['OWNER', 'MANAGER'].includes(user.role)) {
      where.createdById = user.userId;
    }

    const reports = await this.prisma.report.findMany({
      where,
      include: {
        createdBy: { select: { id: true, name: true, avatarUrl: true } },
        attachments: true
      },
      orderBy: { createdAt: 'desc' },
      take: 50
    });

    return { data: reports, total: reports.length };
  }
}

// apps/api/src/reports/reports.controller.ts
import { Controller, Get, Post, Body, UseGuards, Request, Query } from '@nestjs/common';
import { ReportsService } from './reports.service';
import { CreateReportDto } from './dto/create-report.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@Controller('reports')
@UseGuards(JwtAuthGuard)
export class ReportsController {
  constructor(private readonly reportsService: ReportsService) {}

  @Post()
  create(@Body() createReportDto: CreateReportDto, @Request() req) {
    return this.reportsService.create(createReportDto, req.user);
  }

  @Get()
  findAll(@Query('type') type: string, @Request() req) {
    return this.reportsService.findAll(req.user.tenantId, type, req.user);
  }

  @Get('today')
  getTodayReports(@Request() req) {
    return this.reportsService.getTodayReports(req.user.tenantId, req.user);
  }
}

// apps/api/src/reports/dto/create-report.dto.ts
import { IsString, IsOptional, IsArray } from 'class-validator';

export class CreateReportDto {
  @IsString()
  title: string;

  @IsString()
  body: string;

  @IsString()
  @IsOptional()
  category?: string = 'OTHER';

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  tags?: string[];
}

// apps/api/src/chat/chat.module.ts
import { Module } from '@nestjs/common';
import { ChatService } from './chat.service';
import { ChatController } from './chat.controller';
import { ChatGateway } from './chat.gateway';

@Module({
  providers: [ChatService, ChatGateway],
  controllers: [ChatController],
  exports: [ChatService],
})
export class ChatModule {}

// apps/api/src/chat/chat.service.ts
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class ChatService {
  constructor(private prisma: PrismaService) {}

  async getUserChats(user: any) {
    const chats = await this.prisma.chat.findMany({
      where: {
        tenantId: user.tenantId,
        members: { some: { userId: user.userId } }
      },
      include: {
        members: {
          include: {
            user: { select: { id: true, name: true, avatarUrl: true, role: true } }
          }
        },
        messages: {
          orderBy: { createdAt: 'desc' },
          take: 1,
          include: {
            sender: { select: { id: true, name: true, avatarUrl: true } }
          }
        }
      },
      orderBy: { updatedAt: 'desc' }
    });

    return chats.map(chat => ({
      ...chat,
      lastMessage: chat.messages[0] || null,
      unreadCount: 0
    }));
  }

  async getMessages(chatId: string, user: any) {
    // Check access
    const chatMember = await this.prisma.chatMember.findUnique({
      where: { chatId_userId: { chatId, userId: user.userId } }
    });

    if (!chatMember) {
      throw new Error('Chat access denied');
    }

    const messages = await this.prisma.message.findMany({
      where: { chatId, deletedAt: null },
      include: {
        sender: { select: { id: true, name: true, avatarUrl: true } }
      },
      orderBy: { createdAt: 'asc' },
      take: 50
    });

    return { data: messages };
  }

  async sendMessage(chatId: string, body: string, user: any) {
    // Check access
    const chatMember = await this.prisma.chatMember.findUnique({
      where: { chatId_userId: { chatId, userId: user.userId } }
    });

    if (!chatMember?.canMessage) {
      throw new Error('Cannot send message');
    }

    const message = await this.prisma.message.create({
      data: {
        chatId,
        senderId: user.userId,
        body,
      },
      include: {
        sender: { select: { id: true, name: true, avatarUrl: true } }
      }
    });

    // Update chat timestamp
    await this.prisma.chat.update({
      where: { id: chatId },
      data: { updatedAt: new Date() }
    });

    return message;
  }
}

// apps/api/src/chat/chat.controller.ts
import { Controller, Get, Post, Body, Param, UseGuards, Request } from '@nestjs/common';
import { ChatService } from './chat.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';

@Controller('chats')
@UseGuards(JwtAuthGuard)
export class ChatController {
  constructor(private readonly chatService: ChatService) {}

  @Get()
  getUserChats(@Request() req) {
    return this.chatService.getUserChats(req.user);
  }

  @Get(':id/messages')
  getMessages(@Param('id') id: string, @Request() req) {
    return this.chatService.getMessages(id, req.user);
  }

  @Post(':id/messages')
  sendMessage(@Param('id') id: string, @Body('body') body: string, @Request() req) {
    return this.chatService.sendMessage(id, body, req.user);
  }
}

// apps/api/src/chat/chat.gateway.ts
import { WebSocketGateway, SubscribeMessage, MessageBody, WebSocketServer, ConnectedSocket } from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';
import { JwtService } from '@nestjs/jwt';

@WebSocketGateway({
  cors: { origin: process.env.FRONTEND_URL || 'http://localhost:3000' },
  namespace: '/chat',
})
export class ChatGateway {
  @WebSocketServer()
  server: Server;

  constructor(private jwtService: JwtService) {}

  async handleConnection(client: Socket) {
    try {
      const token = client.handshake.auth.token;
      if (!token) {
        client.disconnect();
        return;
      }

      const payload = this.jwtService.verify(token);
      client.data.user = { userId: payload.sub, tenantId: payload.tenantId };
      
      client.emit('connected', { userId: payload.sub });
    } catch (error) {
      client.disconnect();
    }
  }

  @SubscribeMessage('join_chat')
  handleJoinChat(@ConnectedSocket() client: Socket, @MessageBody() data: { chatId: string }) {
    client.join(`chat:${data.chatId}`);
    client.emit('joined_chat', { chatId: data.chatId });
  }

  @SubscribeMessage('typing_start')
  handleTypingStart(@ConnectedSocket() client: Socket, @MessageBody() data: { chatId: string }) {
    const user = client.data.user;
    client.to(`chat:${data.chatId}`).emit('user_typing', {
      userId: user.userId,
      chatId: data.chatId,
    });
  }

  broadcastMessage(chatId: string, message: any) {
    this.server.to(`chat:${chatId}`).emit('message_received', message);
  }
}